# MEC Breakout Agent

This agent is used when the private UPF flow controller cannot be reached
directly by the Portal backend.

The portal stores the desired flow mode. The agents poll the portal through
outbound HTTPS:

- UPF-CN agent: applies the requested mode through the private controller at
  `http://192.168.0.1:9090` and reports the `UPF-CN -> CentralDN` telemetry.
- UPF-E agent: does not change the mode. It reports the `UPF-E -> UPF-CN` and
  `UPF-E -> EdgeDN` telemetry.

No inbound public IP and no SSH between UPF hosts is required.

## Prerequisites

Run the agent on each UPF host where the corresponding OAI UPF container is
already running.

Required on each host:

- Docker
- Docker Compose plugin
- Outbound HTTPS access to portal
- Access to the local Docker socket, because the agent reads counters from the
  local OAI UPF container with `docker exec`

Expected local UPF container names:

- UPF-CN host: `oai-upf`
- UPF-E host: `oai-upf-e`

## Get The Code

Clone the repository on each host and enter the agent directory.

```sh
git clone -b mec-breakout-dashboard https://github.com/SMARTECH-ISI-Athena/mec-agent.git
cd mec-agent
```

If the agent is later split into its own repository, clone that repository
instead and run the same commands from its `mec-agent` directory.

## Configure UPF-CN

On the UPF-CN host:

```sh
cp .env.upf-cn.example .env
nano .env
```

Default values for the current testbed:

```env
PORTAL_BASE_URL=https://back-6gbricks.dedyn.io
AGENT_TOKEN=
FLOW_CONTROLLER_URL=http://192.168.0.1:9090
FLOW_DIRECT_PATH=/flow/all/direct
FLOW_CHAIN_PATH=/flow/all/chain
N6_CIDR=172.31.0.0/24
CENTRAL_DN_LATENCY_TARGET=192.168.11.237
```

Adjust only these values unless the topology changes:

- `AGENT_TOKEN`: set this only if the portal backend is configured with
  `MEC_AGENT_TOKEN`.
- `FLOW_CONTROLLER_URL`: private flow controller URL reachable from UPF-CN.
- `N6_CIDR`: UPF-CN N6 network as seen inside `oai-upf`.
- `CENTRAL_DN_LATENCY_TARGET`: IP used for UPF-CN to CentralDN latency probing.

Start the UPF-CN agent:

```sh
docker compose --profile upf-cn up -d --build
```

Check it:

```sh
docker compose ps
docker compose logs -f mec-agent-cn
```

Expected startup log:

```text
Starting MEC agent node=upf-cn role=controller container=oai-upf portal=https://back-6gbricks.dedyn.io
```

## Configure UPF-E

On the UPF-E host:

```sh
cp .env.upf-e.example .env
nano .env
```

Default values for the current testbed:

```env
PORTAL_BASE_URL=https://back-6gbricks.dedyn.io
AGENT_TOKEN=
N9_CIDR=172.32.1.0/24
N6_CIDR=172.32.1.0/24
UPF_CN_N9_TARGET=172.32.0.134
UPF_E_N9_FILTER_CIDR=172.32.0.134/32
EDGE_DN_FILTER_CIDR=172.33.0.0/24
EDGE_DN_LATENCY_TARGET=172.33.0.100
```

Adjust only these values unless the topology changes:

- `AGENT_TOKEN`: set this only if the portal backend is configured with
  `MEC_AGENT_TOKEN`.
- `N9_CIDR`: UPF-E N9 network as seen inside `oai-upf-e`.
- `N6_CIDR`: UPF-E edge breakout network as seen inside `oai-upf-e`.
- `UPF_CN_N9_TARGET`: UPF-CN N9 IP used for latency probing and filtering.
- `UPF_E_N9_FILTER_CIDR`: exact peer/subnet counted as `UPF-E -> UPF-CN`.
- `EDGE_DN_FILTER_CIDR`: subnet counted as `UPF-E -> EdgeDN`.
- `EDGE_DN_LATENCY_TARGET`: IP used for UPF-E to EdgeDN latency probing.

Start the UPF-E agent:

```sh
docker compose --profile upf-e up -d --build
```

Check it:

```sh
docker compose ps
docker compose logs -f mec-agent-edge
```

Expected startup log:

```text
Starting MEC agent node=upf-e role=telemetry container=oai-upf-e portal=[portal_url]
```

## Interface Detection

The normal agent setup does not require `N9_INTERFACE` or `N6_INTERFACE` in
`.env`.

The agent discovers interfaces automatically:

1. If a latency target is configured, it tries `ip route get <target>` inside
   the local UPF container.
2. Otherwise it matches the configured CIDR against `ip -o -4 addr show`
   inside the local UPF container.

In the current UPF-E topology, both logical links use `eth0`:

```text
oai-upf-e eth0 = N9 + EdgeDN breakout side
oai-upf-e eth1 = N3/access/gNB side
```

Because both UPF-E logical links share `eth0`, raw interface counters are not
enough. The UPF-E agent uses filtered iptables counters when these are set:

```env
UPF_E_N9_FILTER_CIDR=172.32.0.134/32
EDGE_DN_FILTER_CIDR=172.33.0.0/24
```

The rules are counting rules in the UPF container mangle table. They do not
drop, accept, or reroute traffic.

## Portal Check

From any machine with internet access:

```sh
curl https://back-6gbricks.dedyn.io/mec/flow/status
curl https://back-6gbricks.dedyn.io/mec/upf/traffic
```

In `Cloud (Chained)` mode, the portal should show:

```text
UPF-E to UPF-CN       active
UPF-CN to CentralDN   active
UPF-E to EdgeDN       inactive
```

In `Edge (Local Breakout)` mode, the portal should show:

```text
UPF-E to UPF-CN       inactive
UPF-CN to CentralDN   inactive
UPF-E to EdgeDN       active
```

## Start, Stop, Update

Start or update the agent after changing `.env` or code:

```sh
docker compose --profile upf-cn up -d --build
```

or on UPF-E:

```sh
docker compose --profile upf-e up -d --build
```

Stop the agent on UPF-CN:

```sh
docker compose stop mec-agent-cn
```

Stop the agent on UPF-E:

```sh
docker compose stop mec-agent-edge
```

Show logs:

```sh
docker compose logs -f
```

## Optional Validation Traffic

The validation probe is optional. It creates synthetic traffic so the portal UI
can be validated without a live UE traffic source.

Do not enable it during normal measurements.

### UPF-E Validation

On the UPF-E host, add this block to `.env` only when validation traffic is
needed:

```env
VALIDATION_ROLE=upf-e
VALIDATION_UPF_CONTAINER=oai-upf-e
VALIDATION_DIRECT_TARGET=172.33.0.100
VALIDATION_CHAIN_TARGET=172.32.0.134
VALIDATION_PACKET_SIZE=1400
VALIDATION_INTERVAL_SECONDS=0.01
VALIDATION_POLL_SECONDS=2
VALIDATION_N6_CONFIG_SECTION=n6
VALIDATION_N9_CONFIG_SECTION=n9
VALIDATION_EXPECTED_N6_INTERFACE=eth0
VALIDATION_EXPECTED_N9_INTERFACE=eth0
```

Start it:

```sh
docker compose --profile validation up -d --build
docker compose logs -f mec-validation-probe
```

Behavior:

- `direct`: generates `UPF-E -> EdgeDN` traffic.
- `chain`: generates `UPF-E -> UPF-CN` traffic.

### UPF-CN Validation

On the UPF-CN host, add this block to `.env` only when validation traffic is
needed:

```env
VALIDATION_ROLE=upf-cn
VALIDATION_UPF_CONTAINER=oai-upf
VALIDATION_CENTRAL_TARGET=192.168.11.237
VALIDATION_PACKET_SIZE=1400
VALIDATION_INTERVAL_SECONDS=0.01
VALIDATION_POLL_SECONDS=2
VALIDATION_N6_CONFIG_SECTION=n6_internet
VALIDATION_N9_CONFIG_SECTION=n9
VALIDATION_EXPECTED_N6_INTERFACE=eth1
VALIDATION_EXPECTED_N9_INTERFACE=eth0
```

Start it:

```sh
docker compose --profile validation up -d --build
docker compose logs -f mec-validation-probe
```

Behavior:

- `chain`: generates `UPF-CN -> CentralDN` traffic.
- `direct`: generates no UPF-CN validation traffic.

Stop validation traffic on either host:

```sh
docker compose stop mec-validation-probe
docker compose rm -f mec-validation-probe
```

## Troubleshooting

If logs are empty, ask for the specific service:

```sh
docker compose logs -f mec-agent-cn
docker compose logs -f mec-agent-edge
docker compose logs -f mec-validation-probe
```

If latency is missing, check whether the target is reachable from the host or
from inside the UPF container. The agent first tries the UPF container and then
falls back to the agent container.

If a link shows unexpected traffic, check the filter CIDRs first. On UPF-E,
N9 and EdgeDN share the same interface, so the filter CIDRs are what separate
the two logical links.
