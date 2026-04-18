"""Anomaly detection engine — heuristic-based scoring for processes, network, and DLLs."""

import re
from typing import Dict, List
from dataclasses import dataclass, field

from config import (
    WINDOWS_SYSTEM_PROCESSES, SUSPICIOUS_PARENTS,
    SUSPICIOUS_PORTS, HOMOGLYPH_MAP, BENIGN_INJECTION_PROCESSES
)


@dataclass
class Finding:
    category: str  # process, network, dll, injection, persistence
    artifact_id: str
    title: str
    description: str
    risk_score: float  # 0-10
    evidence: Dict
    mitre_techniques: List[str] = field(default_factory=list)
    timestamp: str = ""
    triage_status: str = "malicious"

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 8.0:
            return "critical"
        elif self.risk_score >= 6.0:
            return "high"
        elif self.risk_score >= 4.0:
            return "medium"
        return "low"

    @property
    def requires_manual_review(self) -> bool:
        return self.triage_status == "review"


class AnomalyDetector:
    """Detects anomalies in Volatility plugin output using heuristic rules."""

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze_all(self, plugin_results: Dict) -> List[Finding]:
        self.findings.clear()

        pslist = plugin_results.get("windows.pslist", None)
        pstree = plugin_results.get("windows.pstree", None)
        cmdline = plugin_results.get("windows.cmdline", None)
        netscan = plugin_results.get("windows.netscan", None)
        malfind = plugin_results.get("windows.malware.malfind", None) or plugin_results.get("windows.malfind", None)
        dlllist = plugin_results.get("windows.dlllist", None)
        svcscan = plugin_results.get("windows.svcscan", None)

        process_index = self._build_process_index(pslist.data if pslist and pslist.success else [])

        if pslist and pslist.success:
            self._analyze_processes(process_index, cmdline.data if cmdline and cmdline.success else [])
        if netscan and netscan.success:
            self._analyze_network(netscan.data)
        if malfind and malfind.success:
            self._analyze_injections(malfind.data, process_index)
        if dlllist and dlllist.success:
            self._analyze_dlls(dlllist.data)
        if svcscan and svcscan.success:
            self._analyze_services(svcscan.data)

        self.findings.sort(key=lambda f: f.risk_score, reverse=True)
        return self.findings

    def _build_process_index(self, processes: List[Dict]) -> Dict[int, Dict]:
        process_index: Dict[int, Dict] = {}
        for process in processes:
            pid = process.get("PID") or process.get("pid")
            if pid is None:
                continue
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                continue

            process_index[pid_int] = {
                "name": str(process.get("ImageFileName") or process.get("Name") or process.get("name") or "").lower(),
                "ppid": process.get("PPID") or process.get("ppid"),
                "raw": process,
                "timestamp": process.get("CreateTime") or process.get("create_time") or process.get("StartTime") or process.get("start_time") or "",
            }
        return process_index

    def _analyze_processes(self, process_index: Dict[int, Dict], cmdlines: List[Dict]):
        cmdline_map = {}
        for c in cmdlines:
            pid = c.get("PID") or c.get("pid")
            args = c.get("Args") or c.get("args") or c.get("CommandLine") or ""
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                continue
            cmdline_map[pid_int] = args

        instance_alerted = set()
        for pid, info in process_index.items():
            name = info["name"]
            ppid = info["ppid"]
            try:
                parent_pid = int(ppid)
            except (TypeError, ValueError):
                parent_pid = None
            parent_name = process_index.get(parent_pid, {}).get("name", "unknown") if parent_pid is not None else "unknown"
            cmdline = cmdline_map.get(pid, "")

            self._check_path_anomaly(name, cmdline, pid, info["raw"])
            self._check_parent_anomaly(name, parent_name, pid, info["raw"])
            self._check_scripting_runtime_parent(name, parent_name, ppid, pid, info["raw"])
            self._check_name_spoofing(name, pid, info["raw"])
            self._check_suspicious_cmdline(name, cmdline, pid, info["raw"])

            count = sum(1 for p2 in process_index.values() if p2["name"] == name)
            expected = WINDOWS_SYSTEM_PROCESSES.get(name, {}).get("expected_instances", -1)
            # Avoid flooding findings for common noisy multi-instance behavior.
            if expected > 0 and count > (expected + 2) and name not in instance_alerted:
                instance_alerted.add(name)
                self.findings.append(Finding(
                    category="process", artifact_id=f"PID:{pid}",
                    title=f"Multiple instances of {name}",
                    description=f"Found {count} instances of {name}, expected {expected}. May indicate process masquerading.",
                    risk_score=5.8, evidence=info["raw"],
                    triage_status="review",
                    mitre_techniques=["T1036"],
                ))

    def _is_expected_smss_child(self, name: str, parent_name: str) -> bool:
        smss_children = {"csrss.exe", "winlogon.exe", "wininit.exe"}
        return name.lower() in smss_children and parent_name in {"", "unknown", "smss.exe"}

    def _check_path_anomaly(self, name: str, cmdline: str, pid, raw: Dict):
        expected = WINDOWS_SYSTEM_PROCESSES.get(name, {}).get("expected_path", "")
        if not expected or not cmdline:
            return

        cmdline_lower = cmdline.lower().replace("/", "\\")
        if "\\" not in cmdline_lower:
            return

        expected_lower = expected.lower()

        if expected_lower and expected_lower not in cmdline_lower:
            if "system32" in expected_lower and "system32" not in cmdline_lower:
                self.findings.append(Finding(
                    category="process", artifact_id=f"PID:{pid}",
                    title=f"{name} running from unexpected path",
                    description=f"{name} expected in {expected} but found at: {cmdline[:120]}. Possible masquerading.",
                    risk_score=8.5, evidence=raw,
                    mitre_techniques=["T1036.005"],
                ))

    def _check_parent_anomaly(self, name: str, parent_name: str, pid, raw: Dict):
        if self._is_expected_smss_child(name, parent_name):
            return

        suspicious_list = SUSPICIOUS_PARENTS.get(name, [])
        if parent_name in suspicious_list:
            self.findings.append(Finding(
                category="process", artifact_id=f"PID:{pid}",
                title=f"Suspicious parent-child: {parent_name} -> {name}",
                description=f"{name} was spawned by {parent_name}, which commonly indicates malicious macro execution or exploit.",
                risk_score=8.2, evidence=raw,
                mitre_techniques=["T1059", "T1204.002"],
            ))

        expected_parent = WINDOWS_SYSTEM_PROCESSES.get(name, {}).get("expected_parent", "")
        if parent_name == "unknown" and expected_parent and expected_parent not in ("", "idle"):
            return

        if (
            expected_parent
            and parent_name not in ("", "unknown")
            and expected_parent not in ("", "idle")
            and parent_name != expected_parent
            and name in WINDOWS_SYSTEM_PROCESSES
        ):
            self.findings.append(Finding(
                category="process", artifact_id=f"PID:{pid}",
                title=f"{name} has unexpected parent: {parent_name}",
                description=f"{name} should be child of {expected_parent}, but parent is {parent_name}.",
                risk_score=6.2, evidence=raw,
                mitre_techniques=["T1036"],
            ))

    def _check_scripting_runtime_parent(self, name: str, parent_name: str, ppid, pid, raw: Dict):
        runtime_names = {"python.exe", "pythonw.exe", "python3.exe", "node.exe", "perl.exe", "ruby.exe", "wscript.exe", "cscript.exe"}
        suspicious_parents = {"services.exe", "svchost.exe", "lsass.exe", "winlogon.exe"}

        if name.lower() not in runtime_names:
            return

        if parent_name in suspicious_parents:
            self.findings.append(Finding(
                category="process",
                artifact_id=f"PID:{pid}",
                title=f"Scripting runtime spawned by service host: {name}",
                description=f"{name} was spawned by {parent_name}, which is unusual and can indicate persistence or service-backed execution.",
                risk_score=6.8,
                evidence=raw,
                triage_status="review",
                mitre_techniques=["T1059.006", "T1543.003"],
            ))
            return

        try:
            ppid_int = int(ppid)
        except (TypeError, ValueError):
            ppid_int = -1

        session_id = raw.get("SessionId") or raw.get("session_id") or raw.get("Session") or raw.get("session")
        try:
            session_int = int(session_id)
        except (TypeError, ValueError):
            session_int = 1

        if parent_name == "unknown" and ppid_int > 4 and session_int == 0:
            self.findings.append(Finding(
                category="process",
                artifact_id=f"PID:{pid}",
                title=f"Scripting runtime with unresolved parent: {name}",
                description=f"{name} has unresolved parent PPID {ppid_int}. This can indicate service-backed execution when parent process metadata is missing from snapshot.",
                risk_score=6.2,
                evidence=raw,
                triage_status="review",
                mitre_techniques=["T1059.006", "T1543.003"],
            ))

    def _check_name_spoofing(self, name: str, pid, raw: Dict):
        for orig_char, homoglyphs in HOMOGLYPH_MAP.items():
            for h in homoglyphs:
                if h in name:
                    self.findings.append(Finding(
                        category="process", artifact_id=f"PID:{pid}",
                        title=f"Process name spoofing detected: {name}",
                        description=f"Process name contains homoglyph character(s). Possible attempt to mimic legitimate process.",
                        risk_score=9.5, evidence=raw,
                        mitre_techniques=["T1036.004"],
                    ))
                    return

    def _check_suspicious_cmdline(self, name: str, cmdline: str, pid, raw: Dict):
        if not cmdline:
            return
        cmdline_lower = cmdline.lower()

        patterns = [
            (r"-encodedcommand\s+", "Encoded PowerShell command", 8.5, ["T1059.001", "T1027"]),
            (r"-enc\s+[A-Za-z0-9+/=]{20,}", "Base64 encoded PowerShell", 8.5, ["T1059.001", "T1027"]),
            (r"downloadstring|downloadfile|invoke-webrequest|wget|curl.*http", "Download cradle detected", 8.0, ["T1059.001", "T1105"]),
            (r"invoke-mimikatz|sekurlsa|logonpasswords", "Mimikatz/credential dumping keywords", 9.5, ["T1003.001"]),
            (r"net\s+user\s+/add|net\s+localgroup\s+admin", "Account creation/privilege escalation", 8.0, ["T1136.001"]),
            (r"vssadmin.*delete\s+shadows", "Shadow copy deletion (ransomware indicator)", 9.5, ["T1490"]),
            (r"bcdedit.*recoveryenabled.*no", "Boot recovery disabled (ransomware)", 9.0, ["T1490"]),
            (r"schtasks.*/create|reg\s+add.*\\run", "Persistence mechanism", 7.5, ["T1053.005", "T1547.001"]),
            (r"certutil.*-decode|certutil.*-urlcache", "Certutil abuse for download/decode", 7.5, ["T1140", "T1105"]),
            (r"bitsadmin.*/transfer", "BitsAdmin file transfer", 7.0, ["T1197"]),
        ]

        for pattern, title, score, techniques in patterns:
            if re.search(pattern, cmdline_lower):
                self.findings.append(Finding(
                    category="process", artifact_id=f"PID:{pid}",
                    title=title,
                    description=f"Suspicious command line in {name}: {cmdline[:150]}",
                    risk_score=score, evidence=raw,
                    mitre_techniques=techniques,
                ))

    def _analyze_network(self, connections: List[Dict]):
        ip_connections: Dict[str, int] = {}
        endpoint_findings: Dict[tuple, Dict] = {}

        for conn in connections:
            remote_addr = str(conn.get("ForeignAddr") or conn.get("foreign_addr") or conn.get("RemoteAddr") or "")
            remote_port = conn.get("ForeignPort") or conn.get("foreign_port") or conn.get("RemotePort") or 0
            local_port = conn.get("LocalPort") or conn.get("local_port") or 0
            pid = conn.get("PID") or conn.get("pid") or conn.get("Owner") or ""
            state = str(conn.get("State") or conn.get("state") or "")
            proto = str(conn.get("Proto") or conn.get("proto") or conn.get("Protocol") or "")

            try:
                remote_port = int(remote_port)
                local_port = int(local_port)
            except (ValueError, TypeError):
                remote_port = 0
                local_port = 0

            if remote_addr and remote_addr not in ("0.0.0.0", "::", "*", "127.0.0.1", "::1", "-"):
                ip_connections[remote_addr] = ip_connections.get(remote_addr, 0) + 1

            if remote_addr and remote_addr not in ("0.0.0.0", "::", "*", "127.0.0.1", "::1", "-"):
                endpoint_key = (str(pid), remote_addr)
                record = endpoint_findings.setdefault(endpoint_key, {
                    "evidence": conn,
                    "reasons": [],
                    "risk_score": 0.0,
                    "mitre_techniques": set(),
                    "title": "",
                })
                record["evidence"] = conn

                if remote_port in SUSPICIOUS_PORTS:
                    record["reasons"].append(f"suspicious remote port {remote_port}")
                    record["risk_score"] = max(record["risk_score"], 7.5)
                    record["mitre_techniques"].add("T1071")
                    record["title"] = f"Connection to suspicious port {remote_port}"

                if ip_connections.get(remote_addr, 0) >= 12:
                    record["reasons"].append(f"high-frequency beaconing pattern ({ip_connections[remote_addr]} connections)")
                    record["risk_score"] = max(record["risk_score"], 6.2 if ip_connections[remote_addr] < 20 else 8.0)
                    record["mitre_techniques"].update({"T1071", "T1041"})
                    if not record["title"]:
                        record["title"] = f"High-frequency connections to {remote_addr}"

            if local_port in SUSPICIOUS_PORTS and "LISTEN" in state.upper():
                endpoint_key = (str(pid), f"listen:{int(local_port or 0)}")
                record = endpoint_findings.setdefault(endpoint_key, {
                    "evidence": conn,
                    "reasons": [],
                    "risk_score": 0.0,
                    "mitre_techniques": set(),
                    "title": f"Listening on suspicious port {local_port}",
                })
                record["evidence"] = conn
                record["reasons"].append(f"LISTEN on suspicious local port {local_port}")
                record["risk_score"] = max(record["risk_score"], 8.0)
                record["mitre_techniques"].add("T1571")

            if not remote_port and not (local_port in SUSPICIOUS_PORTS and "LISTEN" in state.upper()):
                continue

        for (pid_key, entity), record in endpoint_findings.items():
            reasons = record["reasons"]
            if not reasons:
                continue

            title = record["title"] or f"Suspicious network activity for {entity}"
            if reasons:
                if len(reasons) == 1:
                    description = f"Process {pid_key} shows {reasons[0]}. Review whether this endpoint is expected."
                else:
                    description = (
                        f"Process {pid_key} shows multiple indicators for {entity}: "
                        + "; ".join(reasons)
                        + ". Review whether this endpoint is expected."
                    )
            else:
                description = f"Process {pid_key} shows suspicious network activity for {entity}. Review whether this endpoint is expected."

            self.findings.append(Finding(
                category="network",
                artifact_id=f"PID:{pid_key}",
                title=title,
                description=description,
                risk_score=record["risk_score"] or 4.8,
                evidence=record["evidence"],
                triage_status="review" if record["risk_score"] < 6.0 else "malicious",
                mitre_techniques=sorted(record["mitre_techniques"] or {"T1071"}),
            ))

    def _analyze_injections(self, malfind_data: List[Dict], process_index: Dict[int, Dict]):
        seen_pids = set()
        for entry in malfind_data:
            pid = entry.get("PID") or entry.get("pid") or ""
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                pid_int = None

            if pid_int is not None:
                if pid_int in seen_pids:
                    continue
                seen_pids.add(pid_int)

            process_meta = process_index.get(pid_int, {}) if pid_int is not None else {}
            name = entry.get("Process") or entry.get("process") or entry.get("Name") or process_meta.get("name") or ""
            protection = str(entry.get("Protection") or entry.get("protection") or "")
            tag = str(entry.get("Tag") or entry.get("tag") or "")
            name_lower = name.lower().strip()
            timestamp = entry.get("CreateTime") or entry.get("create_time") or entry.get("timestamp") or process_meta.get("timestamp") or ""

            score = 7.5
            techniques = ["T1055"]
            title_prefix = "Code injection"
            description_prefix = f"Malfind detected executable memory in {name}."

            if "PAGE_EXECUTE_READWRITE" in protection.upper():
                score = 9.0
                techniques.append("T1055.001")
                description_prefix = f"Malfind detected executable read/write memory in {name}."

            if name_lower in ("lsass.exe", "svchost.exe", "services.exe"):
                score = min(score + 1.0, 10.0)

            if name_lower in BENIGN_INJECTION_PROCESSES:
                # Security tools and vendor scanners often map executable memory that is not
                # immediately actionable; keep the signal but label it cautiously.
                score = min(score, 4.0)
                title_prefix = "Possible code injection"
                description_prefix = (
                    f"Malfind flagged executable memory in {name}, which is common in security/diagnostic tools. "
                    f"Verify whether this is expected for the installed version, vendor-signing state, and runtime context."
                )
                techniques = ["T1055"]
                if "PAGE_EXECUTE_READWRITE" in protection.upper():
                    techniques.append("T1055.001")

            self.findings.append(Finding(
                category="injection", artifact_id=f"PID:{pid}",
                title=f"{title_prefix} in {name} (PID {pid})",
                description=f"{description_prefix} Protection: {protection}. {'Potential process injection signal.' if name_lower in BENIGN_INJECTION_PROCESSES else 'Strong indicator of process injection.'}",
                risk_score=score, evidence=entry,
                timestamp=str(timestamp),
                triage_status="review" if score < 6.0 or name_lower in BENIGN_INJECTION_PROCESSES else "malicious",
                mitre_techniques=techniques,
            ))

    def _analyze_dlls(self, dlllist_data: List[Dict]):
        for entry in dlllist_data:
            pid = entry.get("PID") or entry.get("pid") or ""
            name = entry.get("Name") or entry.get("name") or ""
            path = str(entry.get("Path") or entry.get("path") or entry.get("Base") or "")
            dll_name = str(entry.get("Name") or "").lower()

            path_norm = path.lower().replace("/", "\\")
            if any(d in path_norm for d in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\downloads\\"]):
                self.findings.append(Finding(
                    category="dll", artifact_id=f"PID:{pid}:{dll_name}",
                    title=f"DLL loaded from suspicious path",
                    description=f"Process {pid} loaded {dll_name} from {path}. DLLs in temp/download directories are suspicious.",
                    risk_score=6.5, evidence=entry,
                    mitre_techniques=["T1574.001"],
                ))

    def _analyze_services(self, svcscan_data: List[Dict]):
        for svc in svcscan_data:
            svc_name = str(svc.get("Name") or svc.get("ServiceName") or "")
            binary = str(svc.get("Binary") or svc.get("BinaryPath") or svc.get("ImagePath") or "")
            state = str(svc.get("State") or svc.get("ServiceState") or "")
            start_type = str(svc.get("Start") or svc.get("StartType") or "")

            binary_lower = binary.lower().replace("/", "\\")
            if any(d in binary_lower for d in ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\"]):
                self.findings.append(Finding(
                    category="persistence", artifact_id=f"SVC:{svc_name}",
                    title=f"Service binary in suspicious path: {svc_name}",
                    description=f"Service '{svc_name}' binary at {binary}. Unusual path suggests malicious service installation.",
                    risk_score=8.0, evidence=svc,
                    mitre_techniques=["T1543.003"],
                ))

            if "cmd" in binary_lower or "powershell" in binary_lower:
                self.findings.append(Finding(
                    category="persistence", artifact_id=f"SVC:{svc_name}",
                    title=f"Service executing script interpreter: {svc_name}",
                    description=f"Service '{svc_name}' executes {binary[:100]}. Services running cmd/powershell are highly suspicious.",
                    risk_score=8.5, evidence=svc,
                    mitre_techniques=["T1543.003", "T1059"],
                ))

    def get_risk_summary(self) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            summary[f.risk_level] += 1
        return summary

    def get_findings_by_category(self) -> Dict[str, List[Finding]]:
        cats: Dict[str, List[Finding]] = {}
        for f in self.findings:
            cats.setdefault(f.category, []).append(f)
        return cats
