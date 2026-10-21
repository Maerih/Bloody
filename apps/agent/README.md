# SCIAT Agent (native)

Proprietary — SCIAT AFRICA. The endpoint agent as a single static binary for Windows and Linux
(amd64 and arm64), replacing the script agents in `infra/agent/sciat` step by step.

```
scripts/build-agent.sh            # → dist/agent/<version>/sciat-agent-{linux,windows}-{amd64,arm64}[.exe] + SHA256SUMS
cd apps/agent && go test ./...    # unit + loop tests (fake platform)
```

## Install on a computer

```
# Linux (root)
sudo ./sciat-agent-linux-amd64 install --url https://soc.example.com --account-key sak_… --org-key acme
# Windows (elevated PowerShell)
.\sciat-agent-windows-amd64.exe install --url https://soc.example.com --account-key sak_… --org-key acme
```

`install` enrolls the computer (or keeps the existing enrollment of a script agent — same
configuration files), downloads the isolation helper and the inventory collectors from the
platform, installs itself (`/opt/sciat-agent/sciat-agentd`, `C:\Program Files\SCIAT\Agent\sciat-agent.exe`)
and registers the `sciat-agent` systemd unit / `SCIATAgent` Windows service in place of the
script agent's. Other commands: `status`, `once`, `run`, `uninstall`, `version`.

## What is native today

Enrollment (retries while the platform is busy), check-ins with host facts, isolation state
and platform-address pinning while isolated, isolate / release / hardening commands (allow-list
only — the platform never sends script text), service management, logging.
Inventory, patch status, autostart entries and hardening facts are still collected by the script
collectors installed beside the binary (`inventory` mode) until they are ported.

**Not for production rollout yet:** App Control blocking is not in the native agent, and
installing it replaces the script agent's service. Keep the script agents on customer computers
until the collectors and App Control are native and the packages are signed.

Not yet: code signing (needs SCIAT AFRICA's certificate), MSI / .deb / .rpm packages, native
self-update.
