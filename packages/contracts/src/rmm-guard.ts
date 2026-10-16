import { wildcardMatch } from "./app-control.js";

/**
 * RMM Guard (ESPM, proprietary). Remote monitoring & management and remote-access tools are
 * legitimate software that attackers love: they give full remote control, are signed and are
 * trusted by antivirus. Each organization approves the tools it really uses; any other tool found
 * by the SCIAT Agent (installed software or running process) is reported, and can be blocked
 * through App Control.
 */

export interface RmmTool {
  key: string;
  name: string;
  vendor: string;
  /** Executable names (lower-case, `*` wildcard) seen in running processes. */
  processes: string[];
  /** Installed-software names (case-insensitive substring). */
  software: string[];
}

export const RMM_TOOLS: RmmTool[] = [
  { key: "anydesk", name: "AnyDesk", vendor: "AnyDesk Software", processes: ["anydesk.exe", "anydesk"], software: ["AnyDesk"] },
  { key: "teamviewer", name: "TeamViewer", vendor: "TeamViewer", processes: ["teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe", "teamviewerd"], software: ["TeamViewer"] },
  { key: "screenconnect", name: "ScreenConnect (ConnectWise Control)", vendor: "ConnectWise", processes: ["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "screenconnect.*"], software: ["ScreenConnect", "ConnectWise Control"] },
  { key: "cw_automate", name: "ConnectWise Automate", vendor: "ConnectWise", processes: ["ltsvc.exe", "lttray.exe", "ltsvcmon.exe"], software: ["ConnectWise Automate", "LabTech"] },
  { key: "splashtop", name: "Splashtop", vendor: "Splashtop", processes: ["srservice.exe", "srmanager.exe", "strwinclt.exe", "srstreamer.exe"], software: ["Splashtop"] },
  { key: "atera", name: "Atera", vendor: "Atera Networks", processes: ["ateraagent.exe", "atera*.exe"], software: ["AteraAgent", "Atera "] },
  { key: "ninjaone", name: "NinjaOne", vendor: "NinjaOne", processes: ["ninjarmmagent.exe", "ninjarmmagentpatcher.exe", "ninjarmm*"], software: ["NinjaRMMAgent", "NinjaOne"] },
  { key: "datto_rmm", name: "Datto RMM", vendor: "Kaseya (Datto)", processes: ["aemagent.exe", "cagservice.exe"], software: ["Datto RMM", "CentraStage"] },
  { key: "kaseya_vsa", name: "Kaseya VSA", vendor: "Kaseya", processes: ["agentmon.exe", "kaseya*.exe"], software: ["Kaseya Agent"] },
  { key: "nable_takecontrol", name: "N-able Take Control", vendor: "N-able", processes: ["basupsrvc.exe", "basupsrvcupdater.exe", "basuptshelper.exe"], software: ["Take Control Agent", "N-able Take Control"] },
  { key: "logmein", name: "LogMeIn", vendor: "GoTo", processes: ["logmein.exe", "lmiguardiansvc.exe", "logmeinsystray.exe"], software: ["LogMeIn"] },
  { key: "goto_resolve", name: "GoTo Resolve / GoToAssist", vendor: "GoTo", processes: ["gotoresolve*.exe", "g2ax*.exe"], software: ["GoTo Resolve", "GoToAssist"] },
  { key: "rustdesk", name: "RustDesk", vendor: "RustDesk", processes: ["rustdesk.exe", "rustdesk"], software: ["RustDesk"] },
  { key: "chrome_remote_desktop", name: "Chrome Remote Desktop", vendor: "Google", processes: ["remoting_host.exe", "chrome-remote-desktop-host"], software: ["Chrome Remote Desktop Host"] },
  { key: "remote_utilities", name: "Remote Utilities", vendor: "Remote Utilities", processes: ["rutserv.exe", "rfusclient.exe"], software: ["Remote Utilities"] },
  { key: "netsupport", name: "NetSupport Manager", vendor: "NetSupport", processes: ["client32.exe"], software: ["NetSupport"] },
  { key: "zoho_assist", name: "Zoho Assist", vendor: "Zoho", processes: ["zohoassist*.exe", "zaservice.exe"], software: ["Zoho Assist"] },
  { key: "meshcentral", name: "MeshCentral agent", vendor: "MeshCentral (open source)", processes: ["meshagent.exe", "meshagent"], software: ["Mesh Agent"] },
  { key: "action1", name: "Action1", vendor: "Action1", processes: ["action1_agent.exe", "action1_*.exe"], software: ["Action1"] },
  { key: "tactical_rmm", name: "Tactical RMM", vendor: "AmidaWare (open source)", processes: ["tacticalrmm.exe", "tacticalagent"], software: ["Tactical RMM"] },
  { key: "supremo", name: "Supremo", vendor: "Nanosystems", processes: ["supremo.exe", "supremoservice.exe"], software: ["Supremo"] },
  { key: "vnc", name: "VNC server (RealVNC / TightVNC / UltraVNC)", vendor: "various", processes: ["vncserver.exe", "vncserver-x11*", "tvnserver.exe", "winvnc.exe", "x11vnc"], software: ["VNC Server", "TightVNC", "UltraVNC"] },
];

export function rmmToolByKey(key: string): RmmTool | undefined {
  return RMM_TOOLS.find((t) => t.key === key);
}

export interface RmmEvidence {
  kind: "process" | "software";
  value: string;
}

/** Which tools a host shows, and the evidence (running process or installed software) for each. */
export function detectRmmTools(host: { software: Array<{ name: string; version?: string | null }>; processes: Array<{ name: string; path?: string | null }> }): Map<string, RmmEvidence[]> {
  const found = new Map<string, RmmEvidence[]>();
  const add = (key: string, e: RmmEvidence) => {
    const list = found.get(key) ?? [];
    if (!list.some((x) => x.kind === e.kind && x.value === e.value)) list.push(e);
    found.set(key, list);
  };
  for (const tool of RMM_TOOLS) {
    for (const p of host.processes) {
      const name = (p.path ? p.path.split(/[\\/]/).pop() : p.name) ?? p.name;
      if (tool.processes.some((pattern) => wildcardMatch(pattern, name) || wildcardMatch(pattern, p.name))) add(tool.key, { kind: "process", value: p.path || p.name });
    }
    for (const s of host.software) {
      if (tool.software.some((needle) => s.name.toLowerCase().includes(needle.toLowerCase()))) add(tool.key, { kind: "software", value: s.version ? `${s.name} ${s.version}` : s.name });
    }
  }
  return found;
}

export interface RmmFinding {
  tool: Pick<RmmTool, "key" | "name" | "vendor">;
  approved: boolean;
  endpoints: Array<{ agentId: string; hostname: string; evidence: RmmEvidence[]; seenAt: string }>;
}
