"""VolatileAI configuration."""
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else str(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_csv(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return _split_csv(raw) if raw else []


def _to_int_list(values: Iterable[Any]) -> List[int]:
    parsed: List[int] = []
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            parsed.append(port)
    # Preserve order while deduplicating.
    return list(dict.fromkeys(parsed))


def _normalize_supported_formats(values: Iterable[Any], defaults: List[str]) -> List[str]:
    normalized: List[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        item = value.strip().lower()
        if not item:
            continue
        if not item.startswith("."):
            item = "." + item
        normalized.append(item)
    return list(dict.fromkeys(normalized)) or defaults


def _normalize_plugin_list(values: Iterable[Any], defaults: List[str]) -> List[str]:
    cleaned = [str(v).strip() for v in values if isinstance(v, str) and str(v).strip()]
    deduped = list(dict.fromkeys(cleaned))
    return deduped or defaults


def _normalize_ollama_url(url: str, default: str) -> str:
    candidate = (url or "").strip().rstrip("/")
    if not candidate:
        return default
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return default


def _normalize_ai_provider(provider: str) -> str:
    allowed = {"ollama", "openai", "anthropic", "groq", "opentext"}
    candidate = (provider or "").strip().lower()
    return candidate if candidate in allowed else "ollama"


def _normalize_windows_processes(values: Dict[str, Any], defaults: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(values, dict):
        return deepcopy(defaults)

    normalized = deepcopy(defaults)
    for proc_name, proc_cfg in values.items():
        if not isinstance(proc_name, str) or not isinstance(proc_cfg, dict):
            continue
        key = proc_name.lower().strip()
        if not key:
            continue
        expected_path = str(proc_cfg.get("expected_path", "")).lower()
        expected_parent = str(proc_cfg.get("expected_parent", "")).lower()
        try:
            expected_instances = int(proc_cfg.get("expected_instances", -1))
        except (TypeError, ValueError):
            expected_instances = -1
        normalized[key] = {
            "expected_path": expected_path,
            "expected_parent": expected_parent,
            "expected_instances": expected_instances,
        }
    return normalized


def _normalize_map_of_string_lists(values: Dict[str, Any], defaults: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if not isinstance(values, dict):
        return deepcopy(defaults)

    normalized: Dict[str, List[str]] = {}
    for key, raw_list in values.items():
        if not isinstance(key, str) or not isinstance(raw_list, list):
            continue
        clean_items = [str(item).lower().strip() for item in raw_list if isinstance(item, str) and item.strip()]
        if clean_items:
            normalized[key.lower().strip()] = list(dict.fromkeys(clean_items))

    if not normalized:
        return deepcopy(defaults)
    return normalized


def _normalize_homoglyph_map(values: Dict[str, Any], defaults: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if not isinstance(values, dict):
        return deepcopy(defaults)

    normalized: Dict[str, List[str]] = {}
    for key, chars in values.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(chars, list):
            continue
        clean_chars = [str(char) for char in chars if isinstance(char, str) and char]
        if clean_chars:
            normalized[key.lower().strip()] = list(dict.fromkeys(clean_chars))

    if not normalized:
        return deepcopy(defaults)
    return normalized


def _normalize_risk_levels(values: Dict[str, Any], defaults: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    normalized = deepcopy(defaults)
    if not isinstance(values, dict):
        return normalized

    for level in ("critical", "high", "medium", "low"):
        level_cfg = values.get(level)
        if not isinstance(level_cfg, dict):
            continue
        color = level_cfg.get("color")
        bg = level_cfg.get("bg")
        threshold = level_cfg.get("threshold")

        if isinstance(color, str) and color.strip():
            normalized[level]["color"] = color.strip()
        if isinstance(bg, str) and bg.strip():
            normalized[level]["bg"] = bg.strip()
        try:
            normalized[level]["threshold"] = float(threshold)
        except (TypeError, ValueError):
            pass

    # Enforce descending thresholds to keep risk bands meaningful.
    normalized["critical"]["threshold"] = max(normalized["critical"]["threshold"], normalized["high"]["threshold"])
    normalized["high"]["threshold"] = max(normalized["high"]["threshold"], normalized["medium"]["threshold"])
    normalized["medium"]["threshold"] = max(normalized["medium"]["threshold"], normalized["low"]["threshold"])
    return normalized

BASE_DIR = Path(__file__).parent
# Allows relocating data dir without code changes.
DATA_DIR = Path(_env_str("VOLATILEAI_DATA_DIR", str(BASE_DIR / "idata"))).expanduser()
MITRE_DIR = DATA_DIR / "mitre"
DEMO_DIR = DATA_DIR / "demo_scenarios"
CACHE_DIR = DATA_DIR / "cached_responses"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORTS_DIR = BASE_DIR / "reports" / "output"

APP_NAME = "VolatileAI"
APP_VERSION = "1.0.0"
APP_TAGLINE = "AI-Powered Memory Forensics Investigation Platform"

SUPPORTED_FORMATS = [".raw", ".vmem", ".dmp", ".mem", ".lime", ".img"]

OLLAMA_BASE_URL = _normalize_ollama_url(
    _env_str("OLLAMA_URL", "http://localhost:11434"),
    "http://localhost:11434",
)
OLLAMA_MODEL = _env_str("OLLAMA_MODEL", "phi3:mini")

AI_PROVIDER = _normalize_ai_provider(_env_str("VOLATILEAI_AI_PROVIDER", "ollama"))
AI_TIMEOUT_SECONDS = max(10, _env_int("VOLATILEAI_AI_TIMEOUT", 120))

OPENAI_API_KEY = _env_str("OPENAI_API_KEY", "")
OPENAI_BASE_URL = _env_str("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL = _env_str("OPENAI_MODEL", "gpt-4o-mini")

ANTHROPIC_API_KEY = _env_str("ANTHROPIC_API_KEY", "")
ANTHROPIC_BASE_URL = _env_str("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
ANTHROPIC_MODEL = _env_str("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")

GROQ_API_KEY = _env_str("GROQ_API_KEY", "")
GROQ_BASE_URL = _env_str("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
GROQ_MODEL = _env_str("GROQ_MODEL", "llama-3.1-8b-instant")

# OpenText is treated as an OpenAI-compatible endpoint.
OPENTEXT_API_KEY = _env_str("OPENTEXT_API_KEY", "")
OPENTEXT_BASE_URL = _env_str("OPENTEXT_BASE_URL", "").rstrip("/")
OPENTEXT_MODEL = _env_str("OPENTEXT_MODEL", "gpt-4o-mini")

RISK_LEVELS = {
    "critical": {"color": "#ef4444", "bg": "rgba(239,68,68,0.12)", "threshold": 8.0},
    "high":     {"color": "#f97316", "bg": "rgba(249,115,22,0.12)", "threshold": 6.0},
    "medium":   {"color": "#eab308", "bg": "rgba(234,179,8,0.12)", "threshold": 4.0},
    "low":      {"color": "#22c55e", "bg": "rgba(34,197,94,0.12)", "threshold": 0.0},
}

_DEFAULT_RISK_LEVELS = deepcopy(RISK_LEVELS)

VOLATILITY_PLUGINS_WINDOWS = [
    "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.dlllist", "windows.netscan", "windows.malfind",
    "windows.handles", "windows.svcscan", "windows.filescan",
    "windows.registry.hivelist",
]

_DEFAULT_VOLATILITY_PLUGINS_WINDOWS = list(VOLATILITY_PLUGINS_WINDOWS)

VOLATILITY_PLUGINS_LINUX = [
    "linux.pslist", "linux.pstree", "linux.bash",
    "linux.lsof", "linux.sockstat", "linux.malfind",
    "linux.elfs", "linux.check_syscall",
]

_DEFAULT_VOLATILITY_PLUGINS_LINUX = list(VOLATILITY_PLUGINS_LINUX)

WINDOWS_SYSTEM_PROCESSES = {
    "system": {"expected_path": "", "expected_parent": "idle", "expected_instances": 1},
    "smss.exe": {"expected_path": r"\systemroot\system32\smss.exe", "expected_parent": "system", "expected_instances": 1},
    "csrss.exe": {"expected_path": r"\systemroot\system32\csrss.exe", "expected_parent": "smss.exe", "expected_instances": 2},
    "wininit.exe": {"expected_path": r"\windows\system32\wininit.exe", "expected_parent": "smss.exe", "expected_instances": 1},
    "winlogon.exe": {"expected_path": r"\windows\system32\winlogon.exe", "expected_parent": "smss.exe", "expected_instances": 1},
    "services.exe": {"expected_path": r"\windows\system32\services.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
    "lsass.exe": {"expected_path": r"\windows\system32\lsass.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
    "svchost.exe": {"expected_path": r"\windows\system32\svchost.exe", "expected_parent": "services.exe", "expected_instances": -1},
    "explorer.exe": {"expected_path": r"\windows\explorer.exe", "expected_parent": "userinit.exe", "expected_instances": -1},
    "lsaiso.exe": {"expected_path": r"\windows\system32\lsaiso.exe", "expected_parent": "wininit.exe", "expected_instances": 1},
}

_DEFAULT_WINDOWS_SYSTEM_PROCESSES = deepcopy(WINDOWS_SYSTEM_PROCESSES)

SUSPICIOUS_PARENTS = {
    "cmd.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "iexplore.exe", "firefox.exe", "chrome.exe"],
    "powershell.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe", "wscript.exe", "cscript.exe"],
    "mshta.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "wscript.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "cscript.exe": ["winword.exe", "excel.exe", "outlook.exe"],
    "regsvr32.exe": ["winword.exe", "excel.exe", "cmd.exe", "powershell.exe"],
    "rundll32.exe": ["winword.exe", "excel.exe", "cmd.exe", "powershell.exe"],
    "certutil.exe": ["cmd.exe", "powershell.exe"],
}

_DEFAULT_SUSPICIOUS_PARENTS = deepcopy(SUSPICIOUS_PARENTS)

SUSPICIOUS_PORTS = [4444, 5555, 8888, 1337, 31337, 6666, 6667, 9001, 9050, 9051, 12345, 54321]
KNOWN_C2_PORTS = [443, 8443, 8080, 80, 53]

_DEFAULT_SUSPICIOUS_PORTS = list(SUSPICIOUS_PORTS)
_DEFAULT_KNOWN_C2_PORTS = list(KNOWN_C2_PORTS)

HOMOGLYPH_MAP = {
    "a": ["а", "ɑ"], "c": ["с", "ϲ"], "d": ["ԁ"], "e": ["е", "ε"],
    "i": ["і", "ι"], "o": ["о", "ο"], "p": ["р", "ρ"], "s": ["ѕ", "ꜱ"],
    "x": ["х", "χ"], "y": ["у", "γ"],
}

_DEFAULT_HOMOGLYPH_MAP = deepcopy(HOMOGLYPH_MAP)


def _apply_environment_overrides() -> None:
    global SUPPORTED_FORMATS
    global VOLATILITY_PLUGINS_WINDOWS, VOLATILITY_PLUGINS_LINUX
    global SUSPICIOUS_PORTS, KNOWN_C2_PORTS

    fmt_values = _env_csv("VOLATILEAI_SUPPORTED_FORMATS")
    if fmt_values:
        SUPPORTED_FORMATS = _normalize_supported_formats(fmt_values, SUPPORTED_FORMATS)

    windows_plugins = _env_csv("VOLATILEAI_WINDOWS_PLUGINS")
    if windows_plugins:
        VOLATILITY_PLUGINS_WINDOWS = _normalize_plugin_list(windows_plugins, VOLATILITY_PLUGINS_WINDOWS)

    linux_plugins = _env_csv("VOLATILEAI_LINUX_PLUGINS")
    if linux_plugins:
        VOLATILITY_PLUGINS_LINUX = _normalize_plugin_list(linux_plugins, VOLATILITY_PLUGINS_LINUX)

    suspicious_ports = _env_csv("VOLATILEAI_SUSPICIOUS_PORTS")
    if suspicious_ports:
        SUSPICIOUS_PORTS = _to_int_list(suspicious_ports) or SUSPICIOUS_PORTS

    c2_ports = _env_csv("VOLATILEAI_KNOWN_C2_PORTS")
    if c2_ports:
        KNOWN_C2_PORTS = _to_int_list(c2_ports) or KNOWN_C2_PORTS


def validate_and_normalize_config() -> None:
    """Ensure config values remain safe and usable after edits/overrides."""
    global DATA_DIR, MITRE_DIR, DEMO_DIR, CACHE_DIR, EVIDENCE_DIR, REPORTS_DIR
    global SUPPORTED_FORMATS, OLLAMA_BASE_URL, OLLAMA_MODEL
    global AI_PROVIDER, AI_TIMEOUT_SECONDS
    global OPENAI_BASE_URL, OPENAI_MODEL, OPENAI_API_KEY
    global ANTHROPIC_BASE_URL, ANTHROPIC_MODEL, ANTHROPIC_API_KEY
    global GROQ_BASE_URL, GROQ_MODEL, GROQ_API_KEY
    global OPENTEXT_BASE_URL, OPENTEXT_MODEL, OPENTEXT_API_KEY
    global RISK_LEVELS, VOLATILITY_PLUGINS_WINDOWS, VOLATILITY_PLUGINS_LINUX
    global WINDOWS_SYSTEM_PROCESSES, SUSPICIOUS_PARENTS, SUSPICIOUS_PORTS, KNOWN_C2_PORTS, HOMOGLYPH_MAP

    # Normalize core paths and ensure runtime directories exist.
    DATA_DIR = Path(DATA_DIR).expanduser()
    MITRE_DIR = Path(MITRE_DIR).expanduser()
    DEMO_DIR = Path(DEMO_DIR).expanduser()
    CACHE_DIR = Path(CACHE_DIR).expanduser()
    EVIDENCE_DIR = Path(EVIDENCE_DIR).expanduser()
    REPORTS_DIR = Path(REPORTS_DIR).expanduser()

    for directory in (DATA_DIR, MITRE_DIR, DEMO_DIR, CACHE_DIR, EVIDENCE_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    SUPPORTED_FORMATS = _normalize_supported_formats(SUPPORTED_FORMATS, [".raw", ".vmem", ".dmp", ".mem", ".lime", ".img"])

    OLLAMA_BASE_URL = _normalize_ollama_url(OLLAMA_BASE_URL, "http://localhost:11434")
    OLLAMA_MODEL = OLLAMA_MODEL.strip() if isinstance(OLLAMA_MODEL, str) and OLLAMA_MODEL.strip() else "phi3:mini"

    AI_PROVIDER = _normalize_ai_provider(AI_PROVIDER)
    try:
        AI_TIMEOUT_SECONDS = max(10, int(AI_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        AI_TIMEOUT_SECONDS = 120

    OPENAI_BASE_URL = OPENAI_BASE_URL.strip().rstrip("/") if isinstance(OPENAI_BASE_URL, str) and OPENAI_BASE_URL.strip() else "https://api.openai.com/v1"
    OPENAI_MODEL = OPENAI_MODEL.strip() if isinstance(OPENAI_MODEL, str) and OPENAI_MODEL.strip() else "gpt-4o-mini"
    OPENAI_API_KEY = OPENAI_API_KEY.strip() if isinstance(OPENAI_API_KEY, str) else ""

    ANTHROPIC_BASE_URL = ANTHROPIC_BASE_URL.strip().rstrip("/") if isinstance(ANTHROPIC_BASE_URL, str) and ANTHROPIC_BASE_URL.strip() else "https://api.anthropic.com/v1"
    ANTHROPIC_MODEL = ANTHROPIC_MODEL.strip() if isinstance(ANTHROPIC_MODEL, str) and ANTHROPIC_MODEL.strip() else "claude-3-5-haiku-latest"
    ANTHROPIC_API_KEY = ANTHROPIC_API_KEY.strip() if isinstance(ANTHROPIC_API_KEY, str) else ""

    GROQ_BASE_URL = GROQ_BASE_URL.strip().rstrip("/") if isinstance(GROQ_BASE_URL, str) and GROQ_BASE_URL.strip() else "https://api.groq.com/openai/v1"
    GROQ_MODEL = GROQ_MODEL.strip() if isinstance(GROQ_MODEL, str) and GROQ_MODEL.strip() else "llama-3.1-8b-instant"
    GROQ_API_KEY = GROQ_API_KEY.strip() if isinstance(GROQ_API_KEY, str) else ""

    OPENTEXT_BASE_URL = OPENTEXT_BASE_URL.strip().rstrip("/") if isinstance(OPENTEXT_BASE_URL, str) else ""
    OPENTEXT_MODEL = OPENTEXT_MODEL.strip() if isinstance(OPENTEXT_MODEL, str) and OPENTEXT_MODEL.strip() else "gpt-4o-mini"
    OPENTEXT_API_KEY = OPENTEXT_API_KEY.strip() if isinstance(OPENTEXT_API_KEY, str) else ""

    RISK_LEVELS = _normalize_risk_levels(RISK_LEVELS, _DEFAULT_RISK_LEVELS)
    VOLATILITY_PLUGINS_WINDOWS = _normalize_plugin_list(VOLATILITY_PLUGINS_WINDOWS, _DEFAULT_VOLATILITY_PLUGINS_WINDOWS)
    VOLATILITY_PLUGINS_LINUX = _normalize_plugin_list(VOLATILITY_PLUGINS_LINUX, _DEFAULT_VOLATILITY_PLUGINS_LINUX)

    WINDOWS_SYSTEM_PROCESSES = _normalize_windows_processes(WINDOWS_SYSTEM_PROCESSES, _DEFAULT_WINDOWS_SYSTEM_PROCESSES)
    SUSPICIOUS_PARENTS = _normalize_map_of_string_lists(SUSPICIOUS_PARENTS, _DEFAULT_SUSPICIOUS_PARENTS)
    HOMOGLYPH_MAP = _normalize_homoglyph_map(HOMOGLYPH_MAP, _DEFAULT_HOMOGLYPH_MAP)

    SUSPICIOUS_PORTS = _to_int_list(SUSPICIOUS_PORTS) or _DEFAULT_SUSPICIOUS_PORTS
    KNOWN_C2_PORTS = _to_int_list(KNOWN_C2_PORTS) or _DEFAULT_KNOWN_C2_PORTS


_apply_environment_overrides()
validate_and_normalize_config()
