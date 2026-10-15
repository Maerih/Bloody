# Bloody endpoint isolation (active-response scripts)

Bloody can isolate an endpoint in two modes. Both keep the endpoint reachable by the Bloody
platform and its engine manager, so it can always be **released from the platform**.

| Mode | Blocks | Still reachable |
|---|---|---|
| `lan` | Local networks: 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7, fe80::/10 (stops lateral movement) | Internet, Bloody platform, engine manager, DNS resolvers (port 53) |
| `full` | Everything | Bloody platform, engine manager, DHCP, listed DNS resolvers |

## Install (Wazuh agents)

| OS | Files → `active-response/bin` | Requires |
|---|---|---|
| Linux | `bloody-isolate` (root:wazuh, 0750) | nftables, python3 |
| Windows | `bloody-isolate.cmd` + `bloody-isolate.ps1` | Windows Defender Firewall, PowerShell 5.1+ |

On the Wazuh manager, declare the command and allow it to run on demand:

```xml
<command>
  <name>bloody-isolate</name>
  <executable>bloody-isolate</executable>   <!-- bloody-isolate.cmd on Windows -->
  <timeout_allowed>no</timeout_allowed>
</command>
```

In Bloody, configure the Wazuh integration's **isolation allow-list** with the addresses isolated
endpoints must keep reaching (Wazuh manager, Bloody platform/collectors). Without it, Bloody refuses
to isolate — an endpoint that cannot reach the platform could never be released remotely.

## Manual use / break-glass

```bash
sudo bloody-isolate isolate lan allow=10.0.0.5 dns=1.1.1.1   # Linux
sudo bloody-isolate status
sudo bloody-isolate release
```

```powershell
.\bloody-isolate.ps1 release      # Windows, elevated
```
