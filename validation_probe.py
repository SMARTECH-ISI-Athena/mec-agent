import os
import re
import signal
import subprocess
import time

from agent import request_json


PORTAL_BASE_URL = os.environ.get('PORTAL_BASE_URL', '').rstrip('/')
VALIDATION_ROLE = os.environ.get('VALIDATION_ROLE', 'upf-e')
VALIDATION_UPF_CONTAINER = os.environ.get('VALIDATION_UPF_CONTAINER', 'oai-upf-e')
VALIDATION_DIRECT_TARGET = os.environ.get('VALIDATION_DIRECT_TARGET', '172.33.0.100')
VALIDATION_CHAIN_TARGET = os.environ.get('VALIDATION_CHAIN_TARGET', '172.32.0.134')
VALIDATION_CENTRAL_TARGET = os.environ.get('VALIDATION_CENTRAL_TARGET', '192.168.11.237')
VALIDATION_PACKET_SIZE = os.environ.get('VALIDATION_PACKET_SIZE', '1400')
VALIDATION_INTERVAL_SECONDS = os.environ.get('VALIDATION_INTERVAL_SECONDS', '0.01')
VALIDATION_POLL_SECONDS = float(os.environ.get('VALIDATION_POLL_SECONDS', '2'))
N6_CONFIG_SECTION = os.environ.get('VALIDATION_N6_CONFIG_SECTION', 'n6')
N9_CONFIG_SECTION = os.environ.get('VALIDATION_N9_CONFIG_SECTION', 'n9')
EXPECTED_N6_INTERFACE = os.environ.get('VALIDATION_EXPECTED_N6_INTERFACE', 'eth0')
EXPECTED_N9_INTERFACE = os.environ.get('VALIDATION_EXPECTED_N9_INTERFACE', 'eth0')

current_process = None
current_mode = None
last_config_signature = None
observed_n6_interface = None
observed_n9_interface = None


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
    return run_command(['docker', 'exec', container, 'sh', '-c', command], timeout=timeout)


def read_upf_config():
    return docker_exec(VALIDATION_UPF_CONTAINER, 'cat /openair-upf/etc/config.yaml', timeout=5)


def extract_interface(config_text, section_name):
    pattern = rf'{section_name}:\s*[^\n]*(?:\n\s+.*)*?\n\s+interface_name:\s*([A-Za-z0-9_.:-]+)'
    match = re.search(pattern, config_text)
    return match.group(1) if match else None


def validate_upf_config():
    global last_config_signature, observed_n6_interface, observed_n9_interface

    try:
        config_text = read_upf_config()
    except Exception as exc:
        print(f'Validation probe could not read UPF config: {exc}', flush=True)
        return False

    n6_interface = extract_interface(config_text, N6_CONFIG_SECTION)
    n9_interface = extract_interface(config_text, N9_CONFIG_SECTION)
    observed_n6_interface = n6_interface
    observed_n9_interface = n9_interface
    signature = f'n6={n6_interface};n9={n9_interface}'
    if signature == last_config_signature:
        return False

    last_config_signature = signature
    print(f'{VALIDATION_ROLE} config observed {signature}', flush=True)

    if n6_interface != EXPECTED_N6_INTERFACE:
        print(
            f'WARNING: expected n6 interface {EXPECTED_N6_INTERFACE}, observed {n6_interface}',
            flush=True
        )
    if n9_interface != EXPECTED_N9_INTERFACE:
        print(
            f'WARNING: expected n9 interface {EXPECTED_N9_INTERFACE}, observed {n9_interface}',
            flush=True
        )
    return True


def target_for_mode(mode):
    if VALIDATION_ROLE == 'upf-cn':
        return VALIDATION_CENTRAL_TARGET if mode == 'chain' else None

    if mode == 'direct':
        return VALIDATION_DIRECT_TARGET
    if mode == 'chain':
        return VALIDATION_CHAIN_TARGET
    return None


def interface_for_mode(mode):
    if VALIDATION_ROLE == 'upf-cn':
        return observed_n6_interface if mode == 'chain' else None

    if mode == 'direct':
        return observed_n6_interface
    if mode == 'chain':
        return observed_n9_interface
    return None


def stop_traffic():
    global current_process
    if current_process and current_process.poll() is None:
        current_process.terminate()
        try:
            current_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            current_process.kill()
            current_process.wait(timeout=3)
    current_process = None


def start_traffic(mode):
    global current_process
    target = target_for_mode(mode)
    if not target:
        return

    command = [
        'ping',
        '-i', VALIDATION_INTERVAL_SECONDS,
        '-s', VALIDATION_PACKET_SIZE,
    ]
    interface_name = interface_for_mode(mode)
    if interface_name:
        command.extend(['-I', interface_name])
    command.append(target)
    print(f'Validation traffic mode={mode} target={target} command={" ".join(command)}', flush=True)
    current_process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        text=True
    )


def applied_mode():
    status = request_json(f'{PORTAL_BASE_URL}/mec/flow/status', timeout=5)
    return status.get('appliedMode') or status.get('mode')


def shutdown(_signum, _frame):
    stop_traffic()
    raise SystemExit(0)


def run():
    global current_mode

    if not PORTAL_BASE_URL:
        raise RuntimeError('PORTAL_BASE_URL is required')

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(
        f'Starting MEC validation probe upf={VALIDATION_UPF_CONTAINER} role={VALIDATION_ROLE} '
        f'directTarget={VALIDATION_DIRECT_TARGET} chainTarget={VALIDATION_CHAIN_TARGET} '
        f'centralTarget={VALIDATION_CENTRAL_TARGET}',
        flush=True
    )

    while True:
        try:
            config_changed = validate_upf_config()
            mode = applied_mode()
            if mode != current_mode:
                print(f'Portal applied mode changed {current_mode} -> {mode}', flush=True)
            elif config_changed:
                print(f'{VALIDATION_ROLE} config changed; restarting validation traffic for mode={mode}', flush=True)

            if mode != current_mode or config_changed:
                stop_traffic()
                current_mode = mode
                start_traffic(mode)

            if current_process and current_process.poll() is not None:
                print(f'Validation traffic process exited for mode={current_mode}; restarting', flush=True)
                start_traffic(current_mode)
        except Exception as exc:
            print(f'Validation probe error: {exc}', flush=True)

        time.sleep(VALIDATION_POLL_SECONDS)


if __name__ == '__main__':
    run()
