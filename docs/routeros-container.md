# Watcher Agent on RouterOS (native container)

> ⚠️ **This is a hint, not a turn-key script.** RouterOS 7.x ships a built-in container
> runtime, so the agent can run directly on a MikroTik board instead of a separate Docker
> host. Parameter names, storage layout and addressing differ between RouterOS versions and
> hardware — review every command before pasting it on a live router.

**Image:** `ghcr.io/mapiiik/watcher-agent:latest` (multi-arch: `amd64` + `arm64`)

## Before you start

- **Container support must be enabled** in device-mode **and** the `container` package
  installed. Enabling container device-mode requires **physical confirmation** (cold reboot
  + hold the reset button) — it cannot be done fully remotely.
- **`/api/ping` may not work in-container.** It uses ICMP raw sockets (`CAP_NET_RAW`), and
  RouterOS containers run with a restricted capability set you cannot extend the way
  docker-compose does with `cap_add`. SNMP read, RADIUS disconnect and RouterOS provisioning
  use ordinary UDP/TCP and are unaffected.
- **Image layers need room.** Point `tmpdir` (and ideally `root-dir`) at external storage
  (USB / NVMe) on boards with little onboard flash.
- **Required env vars** — the agent refuses to start without these. Replace every placeholder
  below before starting the container:
  - `AGENT_API_TOKEN`
  - `AGENT_NMS_BASE_URL`
  - `AGENT_NMS_TOKEN`

## 1. Prerequisites (run once)

> ⚠️ This triggers a **confirmation reboot**. Run it on the console, not blindly over SSH.

Enable container mode, then install the matching `container` `.npk` package:

```
/system/device-mode/update container=yes
```

## 2. Networking: give the container an interface and a way out

A veth on a bridge, the bridge holds the gateway address, srcnat for egress:

```
/interface/veth/add name=veth-watcher-agent address=172.20.0.2/24 gateway=172.20.0.1
/interface/bridge/add name=containers
/interface/bridge/port/add bridge=containers interface=veth-watcher-agent
/ip/address/add address=172.20.0.1/24 interface=containers
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.20.0.0/24
```

The agent listens on **80/443 on the veth IP** (`172.20.0.2`). If the NMS must reach it from
outside, add dst-nat from the router's address to `172.20.0.2` and allow it through the
firewall as your policy requires.

## 3. Container runtime config

`registry-url` lets the `remote-image` below pull from GHCR; `tmpdir` should be on roomy
storage:

```
/container/config/set registry-url=https://ghcr.io tmpdir=usb1/pull
```

## 4. Persistent TLS cert storage (optional, recommended)

Keeps self-signed / ACME certs across container restarts. Wire the mount into the container
in step 6.

```
/container/mounts/add name=watcher-agent-certs src=/watcher-agent/certs dst=/app/certs
```

> The mount parameter name on `/container add` varies by RouterOS version — verify on your box
> (e.g. `mounts=watcher-agent-certs`).

## 5. Environment variables

This is the **minimum set** — replace the placeholders. See [README.md](../README.md) for the
full list of `AGENT_*` variables and their defaults.

```
/container/envs
add key=AGENT_API_TOKEN list=watcher_agent value=agent-api-token
add key=AGENT_ID list=watcher_agent value=agent-1
add key=AGENT_NMS_BASE_URL list=watcher_agent value=https://watcher-nms.example
add key=AGENT_NMS_TOKEN list=watcher_agent value=nms-agent-token
```

## 6. Create the container

`envlist` wires in the variable group from step 5. Append `mounts=watcher-agent-certs`
(step 4) to persist certs. `start-on-boot` brings it back after a reboot.

```
/container
add remote-image=ghcr.io/mapiiik/watcher-agent:latest interface=veth-watcher-agent envlist=watcher_agent name=watcher-agent root-dir=watcher-agent workdir=/app start-on-boot=yes logging=yes
```

## 7. Start and verify

```
/container/start [find where name=watcher-agent]
/container/print
/log/print where message~"Watcher Agent"
```
