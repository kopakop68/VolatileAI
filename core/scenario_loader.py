"""Demo scenario loader — loads synthetic Volatility data for demos."""

import json
from typing import Dict, List, Optional

from config import DEMO_DIR


class ScenarioLoader:
    """Loads and manages demo attack scenarios."""

    def __init__(self):
        self._scenarios: Dict[str, Dict] = {}
        self._load_scenarios()

    def _load_scenarios(self):
        if not DEMO_DIR.exists():
            return

        for f in DEMO_DIR.glob("scenario_*.json"):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                sid = data.get("id", f.stem)
                self._scenarios[sid] = data
            except Exception:
                pass

    def list_scenarios(self) -> List[Dict]:
        return [
            {"id": s["id"], "name": s["name"], "description": s.get("description", ""), "os": s.get("os", "windows")}
            for s in self._scenarios.values()
        ]

    def get_scenario(self, scenario_id: str) -> Optional[Dict]:
        return self._scenarios.get(scenario_id)

    def get_plugin_data(self, scenario_id: str) -> Dict[str, List]:
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return {}
        return scenario.get("plugins", {})

    def get_processes(self, scenario_id: str) -> List[Dict]:
        data = self.get_plugin_data(scenario_id)
        return data.get("windows.pslist", [])

    def get_connections(self, scenario_id: str) -> List[Dict]:
        data = self.get_plugin_data(scenario_id)
        return data.get("windows.netscan", [])

    def get_cmdlines(self, scenario_id: str) -> List[Dict]:
        data = self.get_plugin_data(scenario_id)
        return data.get("windows.cmdline", [])

    def get_timeline_events(self, scenario_id: str, findings: list = None) -> List[Dict]:
        """Build a unified timeline from all available data sources."""
        data = self.get_plugin_data(scenario_id)
        events = []

        for proc in data.get("windows.pslist", []):
            ts = proc.get("CreateTime") or proc.get("create_time") or ""
            name = proc.get("ImageFileName") or proc.get("Name") or ""
            pid = proc.get("PID") or proc.get("pid")
            events.append({
                "timestamp": ts, "category": "process",
                "title": f"Process created: {name} (PID {pid})",
                "details": proc, "risk_score": 0,
            })

        for conn in data.get("windows.netscan", []):
            ts = conn.get("Created") or conn.get("created") or ""
            remote = conn.get("ForeignAddr") or conn.get("foreign_addr") or ""
            port = conn.get("ForeignPort") or conn.get("foreign_port") or ""
            pid = conn.get("PID") or conn.get("pid") or ""
            events.append({
                "timestamp": ts, "category": "network",
                "title": f"Connection: PID {pid} -> {remote}:{port}",
                "details": conn, "risk_score": 0,
            })

        if findings:
            for f in findings:
                events.append({
                    "timestamp": f.timestamp if hasattr(f, "timestamp") else "",
                    "category": f.category,
                    "title": f.title,
                    "details": f.evidence if hasattr(f, "evidence") else {},
                    "risk_score": f.risk_score,
                })

        events.sort(key=lambda e: e.get("timestamp", ""))
        return events
