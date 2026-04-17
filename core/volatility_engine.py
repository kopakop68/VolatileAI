"""Volatility 3 integration engine — runs plugins and parses output.

Falls back to demo data when Volatility 3 is not installed or no real dump is loaded.
"""

import subprocess
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field


@dataclass
class EvidenceFile:
    path: str
    filename: str
    size_bytes: int
    size_human: str
    format: str
    md5: str = ""
    sha256: str = ""
    os_profile: str = ""
    is_valid: bool = False


@dataclass
class PluginResult:
    plugin_name: str
    success: bool
    data: List[Dict[str, Any]]
    raw_output: str = ""
    error: str = ""
    row_count: int = 0


class VolatilityEngine:
    """Manages Volatility 3 execution and result parsing."""

    def __init__(self):
        self._vol_available = self._check_volatility()
        self._evidence: Optional[EvidenceFile] = None
        self._results: Dict[str, PluginResult] = {}

    def _check_volatility(self) -> bool:
        try:
            result = subprocess.run(
                ["vol", "--help"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                result = subprocess.run(
                    ["python3", "-m", "volatility3", "--help"],
                    capture_output=True, text=True, timeout=10
                )
                return result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

    def _log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[VolatilityEngine {ts}] {message}", flush=True)

    def _run_vol_command_streaming(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a command while streaming stderr/stdout lines to terminal for live logs.

        We still collect complete stdout for JSON parsing after process exit.
        """
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        try:
            out, err = proc.communicate(timeout=timeout)
            if out:
                stdout_chunks.append(out)
            if err:
                stderr_chunks.append(err)
                for line in err.splitlines():
                    if line.strip():
                        self._log(f"{cmd[-1]}: {line}")
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            if out:
                stdout_chunks.append(out)
            if err:
                stderr_chunks.append(err)
            raise

        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
        )

    @property
    def is_volatility_available(self) -> bool:
        return self._vol_available

    def validate_evidence(self, file_path: str) -> EvidenceFile:
        p = Path(file_path)
        if not p.exists():
            return EvidenceFile(
                path=file_path, filename=p.name, size_bytes=0,
                size_human="N/A", format="unknown", is_valid=False
            )

        size = p.stat().st_size
        size_human = self._human_size(size)
        ext = p.suffix.lower()

        from config import SUPPORTED_FORMATS
        if ext not in SUPPORTED_FORMATS:
            return EvidenceFile(
                path=file_path, filename=p.name, size_bytes=size,
                size_human=size_human, format=ext, is_valid=False
            )

        md5 = self._hash_file(p, "md5")
        sha256 = self._hash_file(p, "sha256")

        self._evidence = EvidenceFile(
            path=str(p.absolute()),
            filename=p.name,
            size_bytes=size,
            size_human=size_human,
            format=ext,
            md5=md5,
            sha256=sha256,
            is_valid=True,
        )
        return self._evidence

    def run_plugin(self, plugin_name: str, file_path: str = None) -> PluginResult:
        path = file_path or (self._evidence.path if self._evidence else None)
        if not path:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="No evidence file specified")

        if not self._vol_available:
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Volatility 3 not installed")

        try:
            self._log(f"Starting plugin: {plugin_name}")
            cmd = ["vol", "-f", path, "-r", "json", plugin_name]
            result = self._run_vol_command_streaming(cmd, timeout=300)

            if result.returncode != 0:
                self._log(f"Primary command failed for {plugin_name}, trying python3 -m volatility3 fallback")
                cmd = ["python3", "-m", "volatility3", "-f", path, "-r", "json", plugin_name]
                result = self._run_vol_command_streaming(cmd, timeout=300)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                self._log(f"Completed plugin: {plugin_name} ({len(data)} rows)")
                return PluginResult(
                    plugin_name=plugin_name, success=True,
                    data=data, raw_output=result.stdout,
                    row_count=len(data)
                )
            else:
                self._log(f"Plugin failed: {plugin_name} (rc={result.returncode})")
                return PluginResult(
                    plugin_name=plugin_name, success=False,
                    data=[], error=result.stderr[:500],
                    raw_output=result.stdout
                )
        except subprocess.TimeoutExpired:
            self._log(f"Plugin timed out: {plugin_name}")
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Plugin timed out after 300 seconds")
        except json.JSONDecodeError:
            self._log(f"JSON parse failed for plugin: {plugin_name}")
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error="Failed to parse JSON output")
        except Exception as e:
            self._log(f"Unhandled plugin error {plugin_name}: {e}")
            return PluginResult(plugin_name=plugin_name, success=False, data=[], error=str(e))

    def run_all_plugins(
        self,
        file_path: str,
        os_type: str = "windows",
        progress_callback: Optional[Callable[[int, int, str, str], None]] = None,
    ) -> Dict[str, PluginResult]:
        from config import VOLATILITY_PLUGINS_WINDOWS, VOLATILITY_PLUGINS_LINUX

        plugins = VOLATILITY_PLUGINS_WINDOWS if os_type == "windows" else VOLATILITY_PLUGINS_LINUX
        self._results.clear()

        total = len(plugins)
        for idx, plugin in enumerate(plugins, start=1):
            if progress_callback:
                progress_callback(idx - 1, total, plugin, "starting")
            result = self.run_plugin(plugin, file_path)
            self._results[plugin] = result
            if progress_callback:
                progress_callback(idx, total, plugin, "completed")

        return self._results

    def get_results(self) -> Dict[str, PluginResult]:
        return self._results

    def load_demo_results(self, scenario_data: Dict) -> Dict[str, PluginResult]:
        """Load pre-built demo scenario data as if Volatility ran."""
        self._results.clear()
        for plugin_name, data in scenario_data.items():
            self._results[plugin_name] = PluginResult(
                plugin_name=plugin_name,
                success=True,
                data=data if isinstance(data, list) else [],
                row_count=len(data) if isinstance(data, list) else 0,
            )
        return self._results

    def _hash_file(self, path: Path, algo: str = "md5") -> str:
        h = hashlib.new(algo)
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "unable_to_compute"

    def _human_size(self, size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
