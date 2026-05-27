# MEC Agent

Polling agent for deployments where the UPF flow controller is only reachable
from the private UPF-CN network.

The portal stores the desired mode. The same agent image can run on both UPF
hosts:

- UPF-CN agent: applies the requested mode through the private controller and
  reports local UPF-CN telemetry.
- UPF-E agent: does not change mode; it only reports local UPF-E telemetry.

Both agents make outbound HTTPS requests to the portal. No SSH between UPF
hosts is required.

## Configure

Run these commands from the `mec-agent` directory:

```sh
cp .env.example .env
```

Edit `.env` on each host and set the latency targets that exist in that
environment. If the portal backend sets `MEC_AGENT_TOKEN`, use the same value
as `AGENT_TOKEN`.

## Run on UPF-CN

```sh
docker compose --profile upf-cn up -d --build
```

## Run on UPF-E

```sh
docker compose --profile upf-e up -d --build
```

## Useful Commands

```sh
docker compose ps
docker compose logs -f
docker compose down
```

If local traffic telemetry is available from the private network, pass:

```sh
-e TRAFFIC_URL=http://private-telemetry-endpoint/traffic
```

or set `TRAFFIC_URL` in `.env`.

If `TRAFFIC_URL` is not set, the agent collects telemetry itself:

- UPF-CN controller agent:
  - `UPF-CN to CentralDN`: byte counters from the local UPF-CN container interface in `N6_CIDR`.
- UPF-E telemetry agent:
  - `UPF-E to UPF-CN`: byte counters from the local UPF-E container interface in `N9_CIDR`.
  - `UPF-E to EdgeDN`: byte counters from the local UPF-E container interface in `N6_CIDR`.

The agent discovers the interface names by running `ip -o -4 addr show` inside
the local UPF container and matching the configured CIDRs. It then reads:

```sh
/sys/class/net/<interface>/statistics/rx_bytes
/sys/class/net/<interface>/statistics/tx_bytes
```

and computes Mbps from byte deltas between poll intervals.

For latency, configure real probe targets on the relevant host:

```sh
-e CENTRAL_DN_LATENCY_TARGET=<central-dn-or-cloud-app-ip>
-e UPF_CN_N9_TARGET=<upf-cn-n9-ip>
-e EDGE_DN_LATENCY_TARGET=<edge-dn-or-edge-app-ip>
```

The latency values are active probes, not UPF counters. The UPF-E agent should
measure `UPF-E to UPF-CN` latency by pinging `UPF_CN_N9_TARGET` from inside the
local `oai-upf-e` container.

The container needs access to the local Docker socket to run `docker exec` on
the local UPF container.

Each agent report uses the same structure. The backend aggregates reports from
both nodes into the single `observed-links` payload consumed by the portal UI:

```json
{
  "mock": false,
  "node": "upf-e",
  "role": "telemetry",
  "mode": "direct",
  "mode-label": "Edge (Local Breakout)",
  "sample": 1,
  "units": "Mbps",
  "observed-links": [
    {
      "name": "UPF-E to EdgeDN",
      "mode": "Edge (Local Breakout)",
      "active": true,
      "source": "UPF-E",
      "destination": "EdgeDN",
      "interface": "N6",
      "rx": 72,
      "tx": 36,
      "latency-ms": 4
    }
  ]
}
```
