"""MITRE ATT&CK mapping engine — maps findings to techniques."""

from typing import Dict, List, Set
from dataclasses import dataclass

@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    detection: str
    url: str


MITRE_TECHNIQUES = {
    "T1003": MitreTechnique("T1003", "OS Credential Dumping", "Credential Access", "Adversaries may attempt to dump credentials to obtain account login and credential material.", "Monitor for unexpected processes interacting with lsass.exe", "https://attack.mitre.org/techniques/T1003"),
    "T1003.001": MitreTechnique("T1003.001", "LSASS Memory", "Credential Access", "Adversaries may attempt to access credential material stored in the process memory of LSASS.", "Monitor for unusual access to lsass.exe, especially from non-system processes", "https://attack.mitre.org/techniques/T1003/001"),
    "T1027": MitreTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion", "Adversaries may attempt to make payloads difficult to discover and analyze by obfuscation.", "Detect encoded/encrypted payloads and scripts", "https://attack.mitre.org/techniques/T1027"),
    "T1036": MitreTechnique("T1036", "Masquerading", "Defense Evasion", "Adversaries may attempt to manipulate features of artifacts to make them appear legitimate.", "Compare process names and paths against known-good baselines", "https://attack.mitre.org/techniques/T1036"),
    "T1036.004": MitreTechnique("T1036.004", "Masquerade Task or Service", "Defense Evasion", "Adversaries may use homoglyph characters to make process names look legitimate.", "Detect Unicode characters in process names", "https://attack.mitre.org/techniques/T1036/004"),
    "T1036.005": MitreTechnique("T1036.005", "Match Legitimate Name or Location", "Defense Evasion", "Adversaries may match or approximate names/locations of legitimate files.", "Verify process binary paths match expected locations", "https://attack.mitre.org/techniques/T1036/005"),
    "T1041": MitreTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Adversaries may steal data by exfiltrating it over an existing C2 channel.", "Monitor for large data transfers to known C2 infrastructure", "https://attack.mitre.org/techniques/T1041"),
    "T1053.005": MitreTechnique("T1053.005", "Scheduled Task", "Persistence", "Adversaries may abuse task scheduling to execute malicious code at system startup or on a scheduled basis.", "Monitor schtasks.exe usage and new scheduled tasks", "https://attack.mitre.org/techniques/T1053/005"),
    "T1055": MitreTechnique("T1055", "Process Injection", "Defense Evasion", "Adversaries may inject code into processes to evade defenses and elevate privileges.", "Monitor for processes with RWX memory regions containing executable code", "https://attack.mitre.org/techniques/T1055"),
    "T1055.001": MitreTechnique("T1055.001", "DLL Injection", "Defense Evasion", "Adversaries may inject DLLs into processes to evade defenses.", "Monitor for unusual DLL loads and RWX memory regions", "https://attack.mitre.org/techniques/T1055/001"),
    "T1055.012": MitreTechnique("T1055.012", "Process Hollowing", "Defense Evasion", "Adversaries may inject code into a suspended process by hollowing out the memory.", "Monitor for processes whose on-disk image differs from in-memory image", "https://attack.mitre.org/techniques/T1055/012"),
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters to execute commands.", "Monitor process creation for cmd.exe, powershell.exe, wscript.exe with suspicious parents", "https://attack.mitre.org/techniques/T1059"),
    "T1059.001": MitreTechnique("T1059.001", "PowerShell", "Execution", "Adversaries may abuse PowerShell for execution.", "Monitor for encoded PowerShell commands and suspicious script execution", "https://attack.mitre.org/techniques/T1059/001"),
    "T1071": MitreTechnique("T1071", "Application Layer Protocol", "Command and Control", "Adversaries may communicate using application layer protocols to avoid detection.", "Monitor for unusual application layer traffic patterns", "https://attack.mitre.org/techniques/T1071"),
    "T1105": MitreTechnique("T1105", "Ingress Tool Transfer", "Command and Control", "Adversaries may transfer tools from an external system into a compromised environment.", "Monitor for downloads using certutil, PowerShell, bitsadmin", "https://attack.mitre.org/techniques/T1105"),
    "T1136.001": MitreTechnique("T1136.001", "Local Account", "Persistence", "Adversaries may create local accounts to maintain access.", "Monitor for 'net user /add' commands and new account creation", "https://attack.mitre.org/techniques/T1136/001"),
    "T1140": MitreTechnique("T1140", "Deobfuscate/Decode Files", "Defense Evasion", "Adversaries may deobfuscate or decode files or information to reveal payloads.", "Monitor for certutil -decode, PowerShell decode operations", "https://attack.mitre.org/techniques/T1140"),
    "T1197": MitreTechnique("T1197", "BITS Jobs", "Defense Evasion", "Adversaries may abuse BITS jobs for persistent execution or file transfer.", "Monitor bitsadmin.exe usage for file downloads", "https://attack.mitre.org/techniques/T1197"),
    "T1204.002": MitreTechnique("T1204.002", "Malicious File", "Execution", "Adversaries may rely on users opening a malicious file for execution.", "Monitor for Office applications spawning command interpreters", "https://attack.mitre.org/techniques/T1204/002"),
    "T1490": MitreTechnique("T1490", "Inhibit System Recovery", "Impact", "Adversaries may delete or remove built-in OS recovery data to prevent recovery.", "Monitor for vssadmin delete shadows and bcdedit commands", "https://attack.mitre.org/techniques/T1490"),
    "T1543.003": MitreTechnique("T1543.003", "Windows Service", "Persistence", "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.", "Monitor for new services with unusual binary paths", "https://attack.mitre.org/techniques/T1543/003"),
    "T1547.001": MitreTechnique("T1547.001", "Registry Run Keys", "Persistence", "Adversaries may add entries to the Run keys in the registry to enable persistence.", "Monitor registry changes to Run/RunOnce keys", "https://attack.mitre.org/techniques/T1547/001"),
    "T1571": MitreTechnique("T1571", "Non-Standard Port", "Command and Control", "Adversaries may communicate using a protocol and port pairing not typically associated.", "Monitor for network traffic on non-standard ports", "https://attack.mitre.org/techniques/T1571"),
    "T1574.001": MitreTechnique("T1574.001", "DLL Search Order Hijacking", "Persistence", "Adversaries may hijack the DLL search order to execute their own malicious payload.", "Monitor for DLLs loaded from unexpected directories", "https://attack.mitre.org/techniques/T1574/001"),
    "T1021.002": MitreTechnique("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "Adversaries may use SMB to move laterally within a network.", "Monitor for PsExec-style remote execution and admin share access", "https://attack.mitre.org/techniques/T1021/002"),
    "T1486": MitreTechnique("T1486", "Data Encrypted for Impact", "Impact", "Adversaries may encrypt data on target systems to interrupt availability.", "Monitor for mass file encryption and ransom note creation", "https://attack.mitre.org/techniques/T1486"),
    "T1562.001": MitreTechnique("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Adversaries may disable security tools to avoid detection.", "Monitor for processes terminating AV/EDR services", "https://attack.mitre.org/techniques/T1562/001"),
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


class MitreMapper:
    """Maps findings to MITRE ATT&CK techniques and generates heatmaps."""

    def __init__(self):
        self.techniques = MITRE_TECHNIQUES

    def get_technique(self, technique_id: str) -> MitreTechnique:
        return self.techniques.get(technique_id)

    def map_findings(self, findings: list) -> Dict[str, List]:
        """Map a list of findings to MITRE techniques. Returns {technique_id: [findings]}."""
        technique_map: Dict[str, List] = {}
        for f in findings:
            for tid in f.mitre_techniques:
                technique_map.setdefault(tid, []).append(f)
        return technique_map

    def get_tactic_heatmap_data(self, findings: list) -> Dict[str, List[Dict]]:
        """Organize detected techniques by tactic for heatmap visualization."""
        technique_map = self.map_findings(findings)
        tactic_data: Dict[str, List[Dict]] = {t: [] for t in TACTIC_ORDER}

        for tid, finding_list in technique_map.items():
            tech = self.techniques.get(tid)
            if tech:
                tactic = tech.tactic
                if tactic in tactic_data:
                    tactic_data[tactic].append({
                        "technique_id": tid,
                        "technique_name": tech.name,
                        "count": len(finding_list),
                        "max_severity": max(f.risk_score for f in finding_list),
                        "findings": finding_list,
                    })

        return tactic_data

    def get_detected_techniques(self, findings: list) -> List[Dict]:
        """Get summary of all detected techniques."""
        technique_map = self.map_findings(findings)
        result = []
        for tid, finding_list in technique_map.items():
            tech = self.techniques.get(tid)
            result.append({
                "technique_id": tid,
                "name": tech.name if tech else tid,
                "tactic": tech.tactic if tech else "Unknown",
                "finding_count": len(finding_list),
                "max_severity": max(f.risk_score for f in finding_list),
                "description": tech.description if tech else "",
                "detection": tech.detection if tech else "",
                "url": tech.url if tech else "",
            })
        result.sort(key=lambda x: x["max_severity"], reverse=True)
        return result

    def get_unique_tactics(self, findings: list) -> Set[str]:
        techniques = self.map_findings(findings)
        tactics = set()
        for tid in techniques:
            tech = self.techniques.get(tid)
            if tech:
                tactics.add(tech.tactic)
        return tactics
