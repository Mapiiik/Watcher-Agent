# Watcher Agent

[![CI](https://github.com/Mapiiik/Watcher-Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Mapiiik/Watcher-Agent/actions/workflows/ci.yml)
[![License: AGPL v3+](https://img.shields.io/badge/License-AGPL%20v3%2B-blue.svg)](LICENSE.md)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg)](go.mod)
[![Image](https://img.shields.io/badge/ghcr.io-mapiiik%2Fwatcher--agent-2496ED.svg)](https://github.com/Mapiiik/Watcher-Agent/pkgs/container/watcher-agent)

A small, self-contained HTTP agent that runs **close to the network** (a Docker host
on-site, or directly on a MikroTik board) and lets a central **Watcher / NMS / CRM**
reach customer-edge devices it cannot talk to directly.

The agent exposes a thin, token-protected HTTP API for four jobs:

| Job | Endpoint | Protocol used towards the device |
| --- | --- | --- |
| **Reachability check** | `POST /api/ping` | ICMP echo (IPv4 & IPv6) |
| **Session teardown** | `POST /api/radius/disconnect` | RADIUS Disconnect (CoA, RFC 3576 / 5176) |
| **Inventory read** | `POST /api/snmp/read/routeros` | SNMP v2c |
| **Auto-provisioning** | `GET /provision/routeros/{type}/{serial}` | SNMP v2c + call to NMS |

It speaks **HTTPS** (self-signed by default, or Let's Encrypt via ACME), supports the
**PROXY protocol** when placed behind a load balancer, and shuts down gracefully by
draining in-flight requests.

---

## How it fits together

```
        ┌─────────────────────┐     HTTPS + Bearer token      ┌───────────────┐
        │  Watcher / NMS / CRM │ ────────────────────────────▶│ Watcher Agent │
        └─────────────────────┘   /api/ping                   │   (on-site)   │
                  ▲                /api/radius/disconnect       └──────┬────────┘
                  │                /api/snmp/read/routeros              │
                  │                                                     │ ICMP / SNMP / RADIUS
                  │                                              ┌──────▼────────┐
                  │  provision script (JSON)                     │ Edge devices  │
                  └──────────────────────────────────────────── │ (RouterOS, …) │
                       /api/agent/provision/routeros.json        └──────┬────────┘
                                                                        │
   RouterOS auto-provisioning flow:                                     │
   device ──GET /provision/routeros/{type}/{serial}──▶ Agent ──SNMP──▶ device
   Agent ──▶ NMS for script ──▶ returns RouterOS script to the device ◀─┘
```

For **provisioning**, the RouterOS device itself calls the agent. The agent SNMP-reads
the device (using the caller's source IP), verifies the serial number, forwards the
inventory to the NMS, and returns the NMS-generated configuration script straight back
to the device as a runnable RouterOS script.

---

## Quick start (Docker Compose)

Pull the prebuilt multi-arch image (`linux/amd64`, `linux/arm64`) from GHCR:

```bash
cp .env.example .env      # edit the values, see Configuration below
docker compose -f compose.production.yaml up -d
```

`compose.production.yaml` also ships a [Watchtower](https://github.com/nicholas-fedor/watchtower)
service that auto-updates the agent whenever a new `:latest` image is published.

To build the image locally instead of pulling it:

```bash
docker compose -f compose.production-build.yaml up -d --build
```

For local development (live `go run`, source mounted into the container):

```bash
docker compose -f compose.dev.yaml up --build
```

> **Customizing.** The tracked `compose.*.yaml` files are templates. To adapt one to your
> environment, copy it to `compose.yaml` (which is git-ignored) and edit it there — a plain
> `docker compose up -d` then picks it up automatically, with no `-f` flag and without
> touching the tracked defaults.

---

## Configuration

All configuration is via environment variables (see [.env.example](.env.example)).
**Required** variables make the agent refuse to start if unset.

| Variable | Required | Default | Description |
| --- | :---: | --- | --- |
| `AGENT_API_TOKEN` | ✅ | — | Bearer token for the `/api/*` endpoints. |
| `AGENT_NMS_BASE_URL` | ✅ | — | Base URL of the NMS used for provisioning. |
| `AGENT_NMS_TOKEN` | ✅ | — | Bearer token the agent uses when calling the NMS. |
| `AGENT_ID` | | `agent-1` | Identifier reported in status / provisioning calls. |
| `AGENT_LISTEN_HTTP` | | `0.0.0.0:80` | HTTP listen address (redirects to HTTPS). |
| `AGENT_LISTEN_HTTPS` | | `0.0.0.0:443` | HTTPS listen address (the actual API). |
| `AGENT_USE_PROXY_PROTOCOL` | | `false` | Expect a PROXY-protocol header on the HTTPS listener. |
| `AGENT_HOSTNAME` | | _(empty)_ | If set, obtain a Let's Encrypt cert via ACME for this host; if empty, a self-signed cert is generated. |
| `AGENT_CERT_DIR` | | `./certs` | Directory where ACME certificates are cached. |
| `AGENT_ROUTEROS_ALLOW_CIDRS` | | `0.0.0.0/0` | Space-separated CIDRs allowed to hit `/provision/routeros/`. **Restrict this.** |
| `AGENT_ROUTEROS_QUERY_TOKEN` | | _(empty)_ | Optional `?token=` value additionally required for provisioning. |
| `AGENT_SNMP_PORT` | | `161` | SNMP UDP port. |
| `AGENT_SNMP_TIMEOUT_MS` | | `1500` | Per-attempt SNMP timeout. |
| `AGENT_SNMP_RETRIES` | | `1` | gosnmp transport-level retries. |
| `AGENT_RADIUS_PORT` | | `1700` | Default RADIUS CoA/Disconnect port (overridable per request). |
| `AGENT_RADIUS_TIMEOUT_MS` | | `1500` | Per-attempt RADIUS timeout. |
| `AGENT_RADIUS_RETRIES` | | `1` | RADIUS retries. |
| `AGENT_DEVICE_TYPES_JSON` | | `{}` | Maps a device-type identifier to its SNMP community (see below). |

`AGENT_DEVICE_TYPES_JSON` is consulted during provisioning to pick the SNMP community
for a given device type:

```json
{
  "router":          { "community": "public" },
  "bridge":          { "community": "public" },
  "customer-router": { "community": "public" },
  "customer-bridge": { "community": "public" }
}
```

---

## API reference

All `/api/*` endpoints require `Authorization: Bearer <AGENT_API_TOKEN>` and return JSON.
Errors use `{ "error": "<code>", "message": "<text>" }`.

### `GET /` &nbsp;·&nbsp; health (no auth)

```json
{ "service": "watcher-agent", "status": "ok", "agent_id": "agent-1" }
```

### `GET /api/status`

Returns uptime and advertised capabilities (the configured device types).

### `POST /api/ping`

> Requires the `NET_RAW` capability (raw ICMP sockets). See [Deployment notes](#deployment-notes).

```jsonc
// request
{ "host": "10.0.0.1", "count": 3, "timeout_ms": 800 }
```
```jsonc
// response
{
  "reachable": true, "target_ip": "10.0.0.1",
  "sent": 3, "received": 3, "lost": 0, "loss_pct": 0,
  "rtt_min_ms": 1.2, "rtt_avg_ms": 1.8, "rtt_max_ms": 2.5
}
```

`host` may be a hostname; if it resolves to both families an IPv6 address is preferred.

### `POST /api/radius/disconnect`

Sends a RADIUS Disconnect-Request to a NAS. `nas_ip` and `secret` are required; the
remaining attributes refine which session is torn down.

```jsonc
// request
{
  "nas_ip": "10.0.0.1", "port": 1700, "secret": "s3cr3t",
  "username": "user@isp", "acct_session_id": "81a0f3c2",
  "framed_ip": "100.64.0.5", "timeout_ms": 1500
}
```
```jsonc
// response
{ "success": true, "result": "Disconnect-ACK", "error_causes": [] }
```

`result` is one of `Disconnect-ACK`, `Disconnect-NAK`, `Timeout after N attempts`,
or `Exception`. Any RFC 5176 Error-Cause values are returned in `error_causes`.

### `POST /api/snmp/read/routeros`

Reads device, interface and IP-address inventory from a RouterOS device over SNMP v2c.

```jsonc
// request
{ "host": "10.99.196.251", "community": "public" }
```
```jsonc
// response (abridged)
{
  "device": {
    "serial_number": "ABC123", "ip_address": "10.99.196.251",
    "name": "edge-1", "board_name": "RB5009", "software_version": "7.x", ...
  },
  "interfaces": [ { "interface_index": 1, "name": "ether1", "mac_address": "…", "ssid": null, … } ],
  "ip_addresses": [ { "interface_index": 8, "ip_address": "10.99.196.251/29", "name": "10.99.196.251" } ]
}
```

> **RouterOS note:** the IP-address inventory comes from the standard `ipAddrTable`
> (`.1.3.6.1.2.1.4.20`). Some RouterOS versions leave this table empty until the IP
> address is re-applied on the device, which surfaces here as
> `SNMP walk failed … for .1.3.6.1.2.1.4.20.1.1: empty response`. RouterOS does **not**
> implement the newer `ipAddressTable` (`.4.34`), so there is no fallback.

### `GET /provision/routeros/{deviceType}/{serial}`

Called **by the RouterOS device itself** during auto-provisioning. Guarded by
`AGENT_ROUTEROS_ALLOW_CIDRS` (source-IP allowlist) and, optionally, a `?token=` matching
`AGENT_ROUTEROS_QUERY_TOKEN`. The agent:

1. SNMP-reads the **serial** from the caller's IP and checks it matches `{serial}`,
2. performs a full SNMP read,
3. POSTs the inventory to `…/api/agent/provision/routeros.json` on the NMS,
4. returns the NMS's RouterOS script verbatim (`Content-Type: text/plain`).

On any failure the response is a RouterOS-runnable error line so the device logs it:

```
:log error "Watcher Agent: SNMP read failed: …"
```

---

## Deployment notes

- **Capabilities.** `/api/ping` opens raw ICMP sockets and needs `NET_RAW`; binding to
  ports 80/443 needs `NET_BIND_SERVICE`. Both are granted in the provided compose files
  via `cap_add`.
- **TLS.** With `AGENT_HOSTNAME` unset the agent serves a freshly generated self-signed
  certificate (30-day validity, regenerated on each restart). Set `AGENT_HOSTNAME` to a
  public name and persist `AGENT_CERT_DIR` to use ACME / Let's Encrypt instead.
- **Graceful shutdown.** On `SIGINT`/`SIGTERM` the agent stops accepting new requests,
  waits for in-flight ones to finish, then shuts down (10 s timeout). Give the container
  enough `stop_grace_period` (the compose files use 60 s).
- **Running on a MikroTik board.** RouterOS 7.x can run the agent as a native container.
  See [docs/routeros-container.md](docs/routeros-container.md) for a starting point
  (note: ICMP ping may be unavailable inside a RouterOS container).

---

## Development

```bash
go vet ./...
go test ./...
golangci-lint run
docker compose -f compose.dev.yaml up --build   # live reload via `go run`
```

CI (GitHub Actions) runs `go mod tidy` verification, `go vet`, golangci-lint and tests
on every push/PR, then builds and pushes the multi-arch image to GHCR on `main`.

### Project layout

```
src/
  main/          process wiring: config, TLS, auth, graceful drain, HTTP servers
  httpapi/       HTTP handlers (root, status, ping, radius, snmp, provision)
  httphelpers/   JSON and RouterOS error responses
  domain/
    snmp/        RouterOS SNMP read (device, interfaces, IP addresses, wireless)
    radius/      RADIUS Disconnect (RFC 3576 / 5176)
  infra/
    icmpengine4/ shared IPv4 ICMP socket + ping engine
    icmpengine6/ shared IPv6 ICMP socket + ping engine
  integration/
    nms/         client for the central NMS provisioning API
```

---

## License

Copyright (C) 2026 Martin Patočka

This program is free software: you can redistribute it and/or modify it under the terms
of the **GNU Affero General Public License** as published by the Free Software Foundation,
either **version 3 of the License, or (at your option) any later version**.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the [GNU AGPL v3](LICENSE.md) for more details.
