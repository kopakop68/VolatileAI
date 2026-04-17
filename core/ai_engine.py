"""AI analysis engine — Ollama integration with caching and RAG."""

import json
import requests
from typing import Dict, List, Optional

from config import (
    AI_PROVIDER,
    AI_TIMEOUT_SECONDS,
    ANTHROPIC_API_KEY,
    ANTHROPIC_BASE_URL,
    ANTHROPIC_MODEL,
    CACHE_DIR,
    GROQ_API_KEY,
    GROQ_BASE_URL,
    GROQ_MODEL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OPENTEXT_API_KEY,
    OPENTEXT_BASE_URL,
    OPENTEXT_MODEL,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)


class AIEngine:
    """Handles AI analysis with provider routing and intelligent caching."""

    def __init__(self):
        self._ollama_available = False
        self._provider = AI_PROVIDER
        self._active_base_url = OLLAMA_BASE_URL
        self._cached_responses: Dict[str, str] = {}
        self._context_data: str = ""
        self._load_cached_responses()

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def provider_label(self) -> str:
        labels = {
            "ollama": "Ollama",
            "openai": "OpenAI",
            "anthropic": "Anthropic Claude",
            "groq": "Groq",
            "opentext": "OpenText",
        }
        return labels.get(self._provider, self._provider.title())

    def _candidate_base_urls(self) -> List[str]:
        candidates = [
            OLLAMA_BASE_URL,
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://172.24.0.1:11434",
        ]
        # Keep order but remove duplicates.
        return list(dict.fromkeys(candidates))

    def check_ollama(self) -> bool:
        self._ollama_available = False
        for base_url in self._candidate_base_urls():
            try:
                r = requests.get(f"{base_url}/api/tags", timeout=5)
                if r.status_code == 200:
                    self._ollama_available = True
                    self._active_base_url = base_url
                    break
            except requests.RequestException:
                continue
        return self._ollama_available

    def _check_openai_compatible(self, base_url: str, api_key: str) -> bool:
        if not base_url or not api_key:
            return False
        try:
            r = requests.get(
                f"{base_url}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=8,
            )
            return r.status_code == 200
        except requests.RequestException:
            return False

    def check_provider(self) -> bool:
        if self._provider == "ollama":
            return self.check_ollama()
        if self._provider == "openai":
            return self._check_openai_compatible(OPENAI_BASE_URL, OPENAI_API_KEY)
        if self._provider == "groq":
            return self._check_openai_compatible(GROQ_BASE_URL, GROQ_API_KEY)
        if self._provider == "opentext":
            return self._check_openai_compatible(OPENTEXT_BASE_URL, OPENTEXT_API_KEY)
        if self._provider == "anthropic":
            return bool(ANTHROPIC_API_KEY)
        return False

    def has_model(self) -> bool:
        """Check if configured model is available. Exact check is only for Ollama."""
        if self._provider != "ollama":
            return True
        if not self._ollama_available:
            self.check_ollama()

        try:
            r = requests.get(f"{self._active_base_url}/api/tags", timeout=5)
            if r.status_code != 200:
                return False

            payload = r.json() if r.content else {}
            models = payload.get("models", []) if isinstance(payload, dict) else []
            names = {m.get("name", "") for m in models if isinstance(m, dict)}
            return OLLAMA_MODEL in names
        except (requests.RequestException, ValueError):
            return False

    @property
    def is_available(self) -> bool:
        return self.check_provider()

    def provider_status(self) -> Dict[str, object]:
        connected = self.check_provider()
        model = {
            "ollama": OLLAMA_MODEL,
            "openai": OPENAI_MODEL,
            "anthropic": ANTHROPIC_MODEL,
            "groq": GROQ_MODEL,
            "opentext": OPENTEXT_MODEL,
        }.get(self._provider, "")

        if connected:
            return {
                "connected": True,
                "dot": "#22c55e",
                "message": f"{self.provider_label} connected — model: {model}",
            }

        if self._provider == "ollama":
            return {
                "connected": False,
                "dot": "#eab308",
                "message": "Ollama unavailable — using cached responses",
            }

        return {
            "connected": False,
            "dot": "#f97316",
            "message": f"{self.provider_label} unavailable or missing API key — using cached responses",
        }

    def set_context(self, findings_summary: str, plugin_data_summary: str):
        self._context_data = f"""You are VolatileAI, an expert memory forensics analyst AI assistant. 
You are analyzing a memory dump and have the following evidence:

=== ANALYSIS FINDINGS ===
{findings_summary}

=== RAW EVIDENCE DATA ===
{plugin_data_summary}

When answering questions:
- Reference specific PIDs, process names, IP addresses, and other concrete evidence
- Map findings to MITRE ATT&CK techniques where applicable
- Provide confidence levels for your assessments
- Suggest follow-up investigation steps
- Be thorough but concise
- Avoid false positives: do not label activity as confirmed malicious unless at least two independent indicators support it
- If evidence is weak or ambiguous, explicitly mark it as "suspicious" or "possible" rather than "confirmed"
- Mention plausible benign explanations when relevant
- Prioritize high-confidence findings and clearly separate them from low-confidence hypotheses
"""

    def ask(self, question: str, scenario_id: str = "") -> str:
        cache_key = self._make_cache_key(question, scenario_id)
        cached = self._cached_responses.get(cache_key)
        if cached:
            return cached

        fuzzy = self._fuzzy_match(question, scenario_id)
        if fuzzy:
            return fuzzy

        if not self.check_provider():
            return self._fallback_response(question)

        if self._provider == "ollama":
            return self._query_ollama(question)
        if self._provider == "openai":
            return self._query_openai_compatible(
                provider_name="OpenAI",
                base_url=OPENAI_BASE_URL,
                api_key=OPENAI_API_KEY,
                model=OPENAI_MODEL,
                question=question,
            )
        if self._provider == "groq":
            return self._query_openai_compatible(
                provider_name="Groq",
                base_url=GROQ_BASE_URL,
                api_key=GROQ_API_KEY,
                model=GROQ_MODEL,
                question=question,
            )
        if self._provider == "opentext":
            return self._query_openai_compatible(
                provider_name="OpenText",
                base_url=OPENTEXT_BASE_URL,
                api_key=OPENTEXT_API_KEY,
                model=OPENTEXT_MODEL,
                question=question,
            )
        if self._provider == "anthropic":
            return self._query_anthropic(question)

        return self._fallback_response(question)

    def _query_ollama(self, question: str) -> str:
        if not self._ollama_available:
            self.check_ollama()

        try:
            prompt = f"{self._context_data}\n\nUser Question: {question}\n\nProvide a detailed forensic analysis response:"

            r = requests.post(
                f"{self._active_base_url}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 1024,
                    }
                },
                timeout=AI_TIMEOUT_SECONDS,
            )

            if r.status_code == 200:
                data = r.json()
                return data.get("response", "No response generated.")

            error_hint = self._extract_error_text(r)

            if r.status_code == 500:
                if "model" in error_hint.lower() and "not found" in error_hint.lower():
                    return (
                        f"Ollama error 500: model '{OLLAMA_MODEL}' is not available. "
                        f"Run: ollama pull {OLLAMA_MODEL}"
                    )
                if "requires more system memory" in error_hint.lower():
                    return self._memory_error_response(error_hint)
                return (
                    "Ollama internal server error (500). "
                    f"Base URL: {self._active_base_url}. "
                    f"Details: {error_hint or 'No error details from server.'}"
                )

            return (
                f"Ollama returned status {r.status_code}. "
                f"Details: {error_hint or 'No error details from server.'}"
            )

        except requests.Timeout:
            return "AI analysis timed out. The model is taking too long to respond."
        except requests.RequestException as e:
            return (
                "Unable to reach Ollama API. "
                f"Base URL: {self._active_base_url}. Error: {str(e)}"
            )
        except Exception as e:
            return f"AI engine error: {str(e)}"

    def _query_openai_compatible(
        self,
        provider_name: str,
        base_url: str,
        api_key: str,
        model: str,
        question: str,
    ) -> str:
        if not base_url:
            return f"{provider_name} base URL is not configured."
        if not api_key:
            return f"{provider_name} API key is missing. Set the required environment variable."

        prompt = f"{self._context_data}\n\nUser Question: {question}\n\nProvide a detailed forensic analysis response:"
        try:
            r = requests.post(
                f"{base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are an expert memory forensics analyst."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1024,
                },
                timeout=AI_TIMEOUT_SECONDS,
            )

            if r.status_code == 200:
                data = r.json()
                choices = data.get("choices", []) if isinstance(data, dict) else []
                if choices and isinstance(choices[0], dict):
                    message = choices[0].get("message", {})
                    if isinstance(message, dict):
                        content = message.get("content", "")
                        if isinstance(content, str) and content.strip():
                            return content
                return f"{provider_name} returned an empty response."

            return (
                f"{provider_name} API returned status {r.status_code}. "
                f"Details: {self._extract_error_text(r) or 'No error details from server.'}"
            )
        except requests.Timeout:
            return f"{provider_name} request timed out."
        except requests.RequestException as e:
            return f"Unable to reach {provider_name} API: {str(e)}"

    def _query_anthropic(self, question: str) -> str:
        if not ANTHROPIC_API_KEY:
            return "Anthropic API key is missing. Set ANTHROPIC_API_KEY."

        prompt = f"{self._context_data}\n\nUser Question: {question}\n\nProvide a detailed forensic analysis response:"
        try:
            r = requests.post(
                f"{ANTHROPIC_BASE_URL}/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 1024,
                    "temperature": 0.3,
                    "system": "You are an expert memory forensics analyst.",
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=AI_TIMEOUT_SECONDS,
            )

            if r.status_code == 200:
                data = r.json()
                blocks = data.get("content", []) if isinstance(data, dict) else []
                if isinstance(blocks, list):
                    texts: List[str] = []
                    for block in blocks:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block.get("text", "")
                            if isinstance(text, str) and text.strip():
                                texts.append(text)
                    if texts:
                        return "\n\n".join(texts)
                return "Anthropic returned an empty response."

            return (
                f"Anthropic API returned status {r.status_code}. "
                f"Details: {self._extract_error_text(r) or 'No error details from server.'}"
            )
        except requests.Timeout:
            return "Anthropic request timed out."
        except requests.RequestException as e:
            return f"Unable to reach Anthropic API: {str(e)}"

    def _extract_error_text(self, response: requests.Response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, dict):
                if isinstance(payload.get("error"), str):
                    return payload["error"].strip()
                if isinstance(payload.get("message"), str):
                    return payload["message"].strip()
                if isinstance(payload.get("error"), dict):
                    err = payload.get("error", {})
                    if isinstance(err.get("message"), str):
                        return err["message"].strip()
        except ValueError:
            pass
        return response.text[:300].strip()

    def _memory_error_response(self, details: str) -> str:
        return (
            "Ollama cannot run the configured model due to RAM limits. "
            f"Details: {details}\n\n"
            "Use a smaller model and retry. Good lightweight options:\n"
            "- phi3:mini\n"
            "- qwen2.5:3b\n"
            "- llama3.2:3b\n"
            "- gemma2:2b\n\n"
            "Then set OLLAMA_MODEL to one of those models and restart the app."
        )

    def _make_cache_key(self, question: str, scenario_id: str = "") -> str:
        normalized = question.lower().strip().rstrip("?").strip()
        return f"{scenario_id}:{normalized}" if scenario_id else normalized

    def _fuzzy_match(self, question: str, scenario_id: str = "") -> Optional[str]:
        q_lower = question.lower().strip()
        q_words = set(q_lower.split())

        best_match = None
        best_score = 0

        for key, response in self._cached_responses.items():
            if scenario_id and not key.startswith(scenario_id + ":"):
                if ":" in key and not key.startswith("general:"):
                    continue

            key_clean = key.split(":", 1)[-1] if ":" in key else key
            key_words = set(key_clean.lower().split())

            if not key_words:
                continue

            overlap = len(q_words & key_words)
            score = overlap / max(len(q_words | key_words), 1)

            if score > best_score and score >= 0.45:
                best_score = score
                best_match = response

        return best_match

    def _fallback_response(self, question: str) -> str:
        provider_hint = {
            "ollama": (
                "Ollama is not currently running or reachable.\n"
                "1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`\n"
                f"2. Pull a small model: `ollama pull {OLLAMA_MODEL}`\n"
                "3. Start Ollama: `ollama serve`"
            ),
            "openai": "Set `OPENAI_API_KEY` (and optionally `OPENAI_MODEL`) to enable live analysis.",
            "anthropic": "Set `ANTHROPIC_API_KEY` (and optionally `ANTHROPIC_MODEL`) to enable live analysis.",
            "groq": "Set `GROQ_API_KEY` (and optionally `GROQ_MODEL`) to enable live analysis.",
            "opentext": "Set `OPENTEXT_API_KEY`, `OPENTEXT_BASE_URL`, and `OPENTEXT_MODEL` to enable live analysis.",
        }
        return (
            "**AI Analysis (Offline Mode)**\n\n"
            f"Configured provider: **{self.provider_label}**\n\n"
            f"{provider_hint.get(self._provider, 'Configure a valid provider and credentials.')}\n\n"
            "If no cached responses are present, AI answers will be limited until the provider is online."
        )

    def _load_cached_responses(self):
        self._cached_responses.clear()
        if not CACHE_DIR.exists():
            return

        for json_file in CACHE_DIR.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for key, val in data.items():
                        if isinstance(val, dict):
                            val = val.get("response", str(val))
                        self._cached_responses[key.lower().strip()] = str(val)
            except Exception:
                pass

    def get_auto_analysis(self, scenario_id: str = "") -> str:
        return self.ask("Summarize the findings and provide an overall assessment", scenario_id)

    def get_attack_narrative(self, scenario_id: str = "") -> str:
        return self.ask("Reconstruct the complete attack timeline and narrative", scenario_id)

    def get_ioc_list(self, scenario_id: str = "") -> str:
        return self.ask("Generate a complete list of indicators of compromise", scenario_id)

    def get_recommendations(self, scenario_id: str = "") -> str:
        return self.ask("What remediation steps and recommendations do you suggest", scenario_id)
