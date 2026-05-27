import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from ipaddress import ip_address, ip_network


PORTAL_BASE_URL = os.environ.get('PORTAL_BASE_URL', '').rstrip('/')
FLOW_CONTROLLER_URL = os.environ.get('FLOW_CONTROLLER_URL', 'http://192.168.0.1:9090').rstrip('/')
FLOW_DIRECT_PATH = os.environ.get('FLOW_DIRECT_PATH', '/flow/all/direct')
FLOW_CHAIN_PATH = os.environ.get('FLOW_CHAIN_PATH', '/flow/all/chain')
TRAFFIC_URL = os.environ.get('TRAFFIC_URL', '').strip()
POLL_INTERVAL_SECONDS = float(os.environ.get('POLL_INTERVAL_SECONDS', '2'))
AGENT_TOKEN = os.environ.get('AGENT_TOKEN', '').strip()
TELEMETRY_ENABLED = os.environ.get('TELEMETRY_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on')
AGENT_ROLE = os.environ.get('AGENT_ROLE', 'controller').strip().lower()
NODE_NAME = os.environ.get('NODE_NAME', 'upf-cn' if AGENT_ROLE == 'controller' else 'upf-e')
DEFAULT_CONTAINER = 'oai-upf' if AGENT_ROLE == 'controller' else 'oai-upf-e'
LOCAL_UPF_CONTAINER = os.environ.get('LOCAL_UPF_CONTAINER', DEFAULT_CONTAINER)
N9_CIDR = os.environ.get('N9_CIDR', '172.32.0.0/24')
N6_CIDR = os.environ.get('N6_CIDR', '172.33.0.0/24')
N9_INTERFACE = os.environ.get('N9_INTERFACE', '').strip()
N6_INTERFACE = os.environ.get('N6_INTERFACE', '').strip()
COUNTER_BACKEND = os.environ.get('COUNTER_BACKEND', 'auto').strip().lower()
UPF_CN_N9_TARGET = os.environ.get('UPF_CN_N9_TARGET', '').strip()
UPF_E_N9_FILTER_CIDR = os.environ.get('UPF_E_N9_FILTER_CIDR', '').strip()
EDGE_DN_FILTER_CIDR = os.environ.get('EDGE_DN_FILTER_CIDR', '').strip()
CENTRAL_DN_FILTER_CIDR = os.environ.get('CENTRAL_DN_FILTER_CIDR', '').strip()
CENTRAL_DN_LATENCY_TARGET = os.environ.get('CENTRAL_DN_LATENCY_TARGET', '').strip()
EDGE_DN_LATENCY_TARGET = os.environ.get('EDGE_DN_LATENCY_TARGET', '').strip()
LATENCY_PROBE_SCOPE = os.environ.get('LATENCY_PROBE_SCOPE', 'auto').strip().lower()

previous_counters = {}
sample_counter = 0
cached_interfaces = {}
cached_ips = {}
reported_probe_failures = set()
installed_counter_rules = set()


def request_json(url, method='GET', payload=None, timeout=10):
    headers = {'Content-Type': 'application/json'}
    if AGENT_TOKEN:
        headers['Authorization'] = f'Bearer {AGENT_TOKEN}'

    data = None
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode('utf-8')
        return json.loads(body) if body else {}


def run_command(command, timeout=8):
    result = subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(command)}: {result.stderr.strip()}")
    return result.stdout.strip()


def docker_exec(container, command, timeout=8):
    docker_command = ['docker', 'exec', container, 'sh', '-c', command]
    return run_command(docker_command, timeout=timeout)


def interface_for_cidr(container, cidr):
    cache_key = f'{container}:{cidr}'
    if cache_key in cached_interfaces:
        return cached_interfaces[cache_key]

    network = ip_network(cidr, strict=False)
    output = docker_exec(container, "ip -o -4 addr show")
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        interface_name = parts[1]
        cidr_address = parts[3]
        ip_value = ip_address(cidr_address.split('/')[0])
        if ip_value in network:
            cached_interfaces[cache_key] = interface_name
            cached_ips[cache_key] = str(ip_value)
            return interface_name

    raise RuntimeError(f'No interface in {container} matches {cidr}')


def interface_for_route(container, target):
    if not target:
        return None

    cache_key = f'{container}:route:{target}'
    if cache_key in cached_interfaces:
        return cached_interfaces[cache_key]

    output = docker_exec(container, f'ip route get {target}')
    parts = output.split()
    if 'dev' not in parts:
        return None

    interface_name = parts[parts.index('dev') + 1]
    cached_interfaces[cache_key] = interface_name
    return interface_name


def ip_for_interface(container, interface_name):
    output = docker_exec(container, f'ip -o -4 addr show dev {interface_name}')
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            return parts[3]
    return None


def ip_for_cidr(container, cidr):
    cache_key = f'{container}:{cidr}'
    if cache_key not in cached_ips:
        interface_for_cidr(container, cidr)
    return cached_ips[cache_key]


def read_counter(container, interface_name, counter):
    value = docker_exec(
        container,
        f'cat /sys/class/net/{interface_name}/statistics/{counter}',
        timeout=5
    )
    return int(value)


def target_to_cidr(target):
    if not target:
        return ''
    if '/' in target:
        return target
    try:
        ip_address(target)
        return f'{target}/32'
    except ValueError:
        return ''


def counter_rule_comment(key, direction, filter_cidr):
    safe_key = re.sub(r'[^a-zA-Z0-9_.:-]', '_', key)
    safe_filter = re.sub(r'[^a-zA-Z0-9_.:-]', '_', filter_cidr)
    return f'mec-agent:{safe_key}:{safe_filter}:{direction}'


def ensure_iptables_counter_rule(container, chain, interface_name, peer_cidr, direction, comment):
    rule_key = f'{container}:{chain}:{interface_name}:{peer_cidr}:{direction}:{comment}'
    if rule_key in installed_counter_rules:
        return

    peer_flag = '-s' if direction == 'rx' else '-d'
    iface_flag = '-i' if direction == 'rx' else '-o'
    check = (
        f"iptables -t mangle -C {chain} {iface_flag} {interface_name} "
        f"{peer_flag} {peer_cidr} -m comment --comment {comment!r}"
    )
    add = (
        f"iptables -t mangle -I {chain} 1 {iface_flag} {interface_name} "
        f"{peer_flag} {peer_cidr} -m comment --comment {comment!r}"
    )

    try:
        docker_exec(container, check, timeout=5)
    except Exception:
        docker_exec(container, add, timeout=5)

    installed_counter_rules.add(rule_key)


def read_iptables_counter_bytes(container, comment):
    output = docker_exec(container, 'iptables-save -t mangle -c', timeout=5)
    for line in output.splitlines():
        if f'--comment "{comment}"' not in line:
            continue
        match = re.match(r'\[(\d+):(\d+)\]', line)
        if match:
            return int(match.group(2))
    return 0


def read_filtered_counters(container, key, interface_name, peer_cidr):
    rx_comment = counter_rule_comment(key, 'rx', peer_cidr)
    tx_comment = counter_rule_comment(key, 'tx', peer_cidr)
    ensure_iptables_counter_rule(container, 'PREROUTING', interface_name, peer_cidr, 'rx', rx_comment)
    ensure_iptables_counter_rule(container, 'POSTROUTING', interface_name, peer_cidr, 'tx', tx_comment)
    return {
        'rx_bytes': read_iptables_counter_bytes(container, rx_comment),
        'tx_bytes': read_iptables_counter_bytes(container, tx_comment)
    }


def read_link_mbps(key, container, cidr, interface_override=None, route_target=None, filter_cidr=None):
    interface_name = interface_override or interface_for_route(container, route_target) or interface_for_cidr(container, cidr)
    now = time.time()
    backend = 'interface'
    if filter_cidr and COUNTER_BACKEND in ('auto', 'iptables'):
        try:
            counters = read_filtered_counters(container, key, interface_name, filter_cidr)
            rx_bytes = counters['rx_bytes']
            tx_bytes = counters['tx_bytes']
            backend = 'iptables-filter'
        except Exception as exc:
            if COUNTER_BACKEND == 'iptables':
                raise
            failure_key = f'iptables-counter:{container}:{key}:{interface_name}:{filter_cidr}:{exc}'
            if failure_key not in reported_probe_failures:
                reported_probe_failures.add(failure_key)
                print(f'Filtered counter failed for {key}, falling back to interface counters: {exc}', flush=True)
            rx_bytes = read_counter(container, interface_name, 'rx_bytes')
            tx_bytes = read_counter(container, interface_name, 'tx_bytes')
            backend = 'interface-fallback'
    else:
        rx_bytes = read_counter(container, interface_name, 'rx_bytes')
        tx_bytes = read_counter(container, interface_name, 'tx_bytes')
    previous = previous_counters.get(key)
    previous_counters[key] = {
        'timestamp': now,
        'rx_bytes': rx_bytes,
        'tx_bytes': tx_bytes
    }

    if not previous:
        return {
            'interface': interface_name,
            'local-ip': ip_for_interface(container, interface_name),
            'counter-backend': backend,
            'filter-cidr': filter_cidr,
            'rx': 0,
            'tx': 0
        }

    elapsed = max(now - previous['timestamp'], 0.001)
    rx_mbps = max(rx_bytes - previous['rx_bytes'], 0) * 8 / elapsed / 1_000_000
    tx_mbps = max(tx_bytes - previous['tx_bytes'], 0) * 8 / elapsed / 1_000_000

    return {
        'interface': interface_name,
        'local-ip': ip_for_interface(container, interface_name),
        'counter-backend': backend,
        'filter-cidr': filter_cidr,
        'rx': round(rx_mbps, 2),
        'tx': round(tx_mbps, 2)
    }


def parse_ping_latency(output):
    match = re.search(r'(?:rtt|round-trip).* = [^/]+/([^/]+)/', output)
    if not match:
        return None
    return round(float(match.group(1)), 2)


def ping_latency_ms(target, container=None):
    if not target:
        return None

    command = f'ping -c 3 -W 1 {target}'

    if LATENCY_PROBE_SCOPE in ('container', 'auto') and container:
        try:
            return parse_ping_latency(docker_exec(container, command, timeout=6))
        except Exception as exc:
            failure_key = f'container:{container}:{target}:{exc}'
            if failure_key not in reported_probe_failures:
                reported_probe_failures.add(failure_key)
                print(f'Container latency probe failed for {target}: {exc}', flush=True)
            if LATENCY_PROBE_SCOPE == 'container':
                return None

    if LATENCY_PROBE_SCOPE in ('agent', 'auto'):
        try:
            return parse_ping_latency(run_command(command.split(), timeout=6))
        except Exception as exc:
            failure_key = f'agent:{target}:{exc}'
            if failure_key not in reported_probe_failures:
                reported_probe_failures.add(failure_key)
                print(f'Agent latency probe failed for {target}: {exc}', flush=True)
            return None

    if LATENCY_PROBE_SCOPE not in ('container', 'agent', 'auto'):
        print(f'Unsupported LATENCY_PROBE_SCOPE={LATENCY_PROBE_SCOPE}', flush=True)
        return None

    return None


def post_controller(path):
    url = f'{FLOW_CONTROLLER_URL}{path}'
    request = urllib.request.Request(url, method='POST')
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode('utf-8')
        try:
            parsed_body = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed_body = body

        return {
            'statusCode': response.status,
            'body': parsed_body,
            'url': url
        }


def mode_label(mode):
    if mode == 'direct':
        return 'Edge (Local Breakout)'
    if mode == 'chain':
        return 'Cloud (Chained)'
    return 'Unknown'


def collect_traffic(mode):
    global sample_counter
    sample_counter += 1
    cloud_active = mode in ('chain', 'unknown')
    edge_active = mode == 'direct'

    observed_links = []
    upf_e_n9_filter = UPF_E_N9_FILTER_CIDR or target_to_cidr(UPF_CN_N9_TARGET)

    if AGENT_ROLE == 'controller':
        cn_n6 = read_link_mbps(
            f'{NODE_NAME}-n6',
            LOCAL_UPF_CONTAINER,
            N6_CIDR,
            interface_override=N6_INTERFACE,
            route_target=CENTRAL_DN_LATENCY_TARGET,
            filter_cidr=CENTRAL_DN_FILTER_CIDR
        )
        observed_links.append({
            'name': 'UPF-CN to CentralDN',
            'mode': 'Cloud (Chained)',
            'active': cloud_active,
            'source': 'UPF-CN',
            'destination': 'CentralDN',
            'interface': f"N6 ({cn_n6['interface']})",
            'local-ip': cn_n6['local-ip'],
            'counter-backend': cn_n6['counter-backend'],
            'filter-cidr': cn_n6['filter-cidr'],
            'rx': cn_n6['rx'],
            'tx': cn_n6['tx'],
            'latency-ms': ping_latency_ms(CENTRAL_DN_LATENCY_TARGET, container=LOCAL_UPF_CONTAINER),
            'note': 'Measured on UPF-CN N6 interface counters'
        })

    if AGENT_ROLE == 'telemetry':
        e_n9 = read_link_mbps(
            f'{NODE_NAME}-n9',
            LOCAL_UPF_CONTAINER,
            N9_CIDR,
            interface_override=N9_INTERFACE,
            route_target=UPF_CN_N9_TARGET,
            filter_cidr=upf_e_n9_filter
        )
        e_n6 = read_link_mbps(
            f'{NODE_NAME}-n6',
            LOCAL_UPF_CONTAINER,
            N6_CIDR,
            interface_override=N6_INTERFACE,
            route_target=EDGE_DN_LATENCY_TARGET,
            filter_cidr=EDGE_DN_FILTER_CIDR
        )
        observed_links.extend([
            {
                'name': 'UPF-E to UPF-CN',
                'mode': 'Cloud (Chained)',
                'active': cloud_active,
                'source': 'UPF-E',
                'destination': 'UPF-CN',
                'interface': f"N9 ({e_n9['interface']})",
                'local-ip': e_n9['local-ip'],
                'counter-backend': e_n9['counter-backend'],
                'filter-cidr': e_n9['filter-cidr'],
                'rx': e_n9['rx'],
                'tx': e_n9['tx'],
                'latency-ms': ping_latency_ms(UPF_CN_N9_TARGET, container=LOCAL_UPF_CONTAINER),
                'note': 'Measured on UPF-E N9 interface counters'
            },
            {
                'name': 'UPF-E to EdgeDN',
                'mode': 'Edge (Local Breakout)',
                'active': edge_active,
                'source': 'UPF-E',
                'destination': 'EdgeDN',
                'interface': f"N6 ({e_n6['interface']})",
                'local-ip': e_n6['local-ip'],
                'counter-backend': e_n6['counter-backend'],
                'filter-cidr': e_n6['filter-cidr'],
                'rx': e_n6['rx'],
                'tx': e_n6['tx'],
                'latency-ms': ping_latency_ms(EDGE_DN_LATENCY_TARGET, container=LOCAL_UPF_CONTAINER),
                'note': 'Measured on UPF-E N6 interface counters'
            }
        ])

    return {
        'mock': False,
        'node': NODE_NAME,
        'role': AGENT_ROLE,
        'mode': mode,
        'mode-label': mode_label(mode),
        'sample': sample_counter,
        'units': 'Mbps',
        'observed-links': observed_links
    }


def fetch_traffic(mode):
    if not TRAFFIC_URL:
        if TELEMETRY_ENABLED:
            try:
                return collect_traffic(mode)
            except Exception as exc:
                print(f'Telemetry collection failed node={NODE_NAME} role={AGENT_ROLE}: {exc}', flush=True)
                return {
                    'status': 'error',
                    'message': f'Failed to collect local traffic telemetry: {exc}'
                }
        return None

    try:
        return request_json(TRAFFIC_URL, timeout=5)
    except Exception as exc:
        return {
            'status': 'error',
            'message': f'Failed to fetch local traffic telemetry: {exc}'
        }


def report(mode, revision, status, response=None, traffic=None):
    payload = {
        'node': NODE_NAME,
        'role': AGENT_ROLE,
        'mode': mode,
        'revision': revision,
        'status': status
    }
    if response is not None:
        payload['response'] = response
    if traffic is not None:
        payload['traffic'] = traffic

    result = request_json(f'{PORTAL_BASE_URL}/mec/agent/report', method='POST', payload=payload)
    link_count = len((traffic or {}).get('observed-links') or [])
    print(
        f'Reported node={NODE_NAME} role={AGENT_ROLE} mode={mode} '
        f'revision={revision} status={status} links={link_count}',
        flush=True
    )
    return result


def apply_mode(mode):
    if mode == 'direct':
        return post_controller(FLOW_DIRECT_PATH)
    if mode == 'chain':
        return post_controller(FLOW_CHAIN_PATH)
    raise ValueError(f'Unsupported mode: {mode}')


def run():
    if not PORTAL_BASE_URL:
        raise RuntimeError('PORTAL_BASE_URL is required')
    if AGENT_ROLE not in ('controller', 'telemetry'):
        raise RuntimeError('AGENT_ROLE must be controller or telemetry')

    last_applied_revision = None
    loop_count = 0

    print(
        f'Starting MEC agent node={NODE_NAME} role={AGENT_ROLE} '
        f'container={LOCAL_UPF_CONTAINER} portal={PORTAL_BASE_URL}',
        flush=True
    )

    while True:
        try:
            loop_count += 1
            desired = request_json(f'{PORTAL_BASE_URL}/mec/agent/desired')
            mode = desired.get('desiredMode')
            revision = desired.get('revision')
            pending = desired.get('pending')

            if loop_count == 1 or loop_count % 30 == 0:
                print(
                    f'Polling ok node={NODE_NAME} role={AGENT_ROLE} '
                    f'desiredMode={mode} revision={revision} pending={pending}',
                    flush=True
                )

            should_apply = AGENT_ROLE == 'controller' and pending and mode in ('direct', 'chain')
            if should_apply and revision != last_applied_revision:
                print(f'Applying mode={mode} revision={revision}', flush=True)
                controller_response = apply_mode(mode)
                traffic = fetch_traffic(mode)
                report(mode, revision, 'success', response=controller_response, traffic=traffic)
                last_applied_revision = revision
            else:
                traffic = fetch_traffic(mode) if mode in ('direct', 'chain') else None
                if traffic is not None:
                    report(mode, revision, 'success', traffic=traffic)

        except urllib.error.HTTPError as exc:
            print(f'HTTP error: {exc.code} {exc.reason}', flush=True)
        except Exception as exc:
            print(f'Agent error: {exc}', flush=True)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == '__main__':
    run()
