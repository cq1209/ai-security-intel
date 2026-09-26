"""MITRE ATT&CK and ATLAS attack-chain mapping."""
from __future__ import annotations

from typing import Dict, List, Tuple

_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Each rule maps trigger keywords to a tactic and technique in a logical attack chain.
_RULES: List[Tuple[Tuple[str, ...], str, str, str, str]] = [
    (
        ("prompt injection", "prompt-injection"),
        "Execution",
        "AML.T0051",
        "LLM Prompt Injection",
        "The vulnerability enables crafted prompts to manipulate model behavior.",
    ),
    (
        ("jailbreak",),
        "Execution",
        "AML.T0054",
        "LLM Jailbreak Injection",
        "The vulnerability allows bypassing model safety constraints.",
    ),
    (
        ("training data poisoning", "data poisoning", "model poisoning"),
        "Resource Development",
        "AML.T0020",
        "Poison Training Data",
        "The vulnerability allows corrupting training data to alter model behavior.",
    ),
    (
        ("system prompt extraction", "prompt extraction", "model extraction", "model theft"),
        "Collection",
        "AML.T0056",
        "Extract LLM System Prompt",
        "The vulnerability allows extracting model or system information.",
    ),
    (
        (
            "remote code execution",
            "rce",
            "arbitrary code execution",
            "code execution",
            "code injection",
            "deserialization",
        ),
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
        "The vulnerability allows executing arbitrary code on an exposed service.",
    ),
    (
        ("sql injection", "sqli"),
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
        "The vulnerability allows database query manipulation through untrusted input.",
    ),
    (
        ("cross-site scripting", "xss"),
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
        "The vulnerability allows injecting client-side scripts served to other users.",
    ),
    (
        ("server-side request forgery", "ssrf"),
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
        "The vulnerability allows the server to issue requests on the attacker's behalf.",
    ),
    (
        ("authentication bypass", "auth bypass", "broken authentication", "improper authentication"),
        "Initial Access",
        "T1078",
        "Valid Accounts",
        "The vulnerability allows bypassing authentication to gain unauthorized access.",
    ),
    (
        ("command injection", "os command injection", "arbitrary command", "shell command"),
        "Execution",
        "T1059",
        "Command and Scripting Interpreter",
        "The vulnerability allows executing operating-system commands.",
    ),
    (
        (
            "buffer overflow",
            "heap overflow",
            "stack overflow",
            "use-after-free",
            "memory corruption",
        ),
        "Execution",
        "T1203",
        "Exploitation for Client Execution",
        "The vulnerability allows memory corruption leading to control-flow hijack.",
    ),
    (
        ("privilege escalation", "elevation of privilege", "privesc"),
        "Privilege Escalation",
        "T1068",
        "Exploitation for Privilege Escalation",
        "The vulnerability allows obtaining higher privileges.",
    ),
    (
        (
            "path traversal",
            "directory traversal",
            "arbitrary file read",
            "local file inclusion",
            "lfi",
            "information disclosure",
            "sensitive information disclosure",
        ),
        "Collection",
        "T1005",
        "Data from Local System",
        "The vulnerability allows reading files or sensitive data from the system.",
    ),
    (
        ("arbitrary file write", "file upload", "webshell"),
        "Persistence",
        "T1505",
        "Server Software Component",
        "The vulnerability allows writing files or deploying web shells for persistence.",
    ),
    (
        ("denial of service", "dos", "resource exhaustion", "uncontrolled resource consumption"),
        "Impact",
        "T1499",
        "Endpoint Denial of Service",
        "The vulnerability allows exhausting resources and disrupting service.",
    ),
]


def _tactic_rank(tactic: str) -> int:
    try:
        return _TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(_TACTIC_ORDER)


def map_attack_chain(text: str) -> List[Dict]:
    lowered = text.lower()
    matched: List[Dict] = []
    seen: set = set()
    for keywords, tactic, technique_id, technique_name, description in _RULES:
        if not any(keyword in lowered for keyword in keywords):
            continue
        if technique_id in seen:
            continue
        seen.add(technique_id)
        matched.append(
            {
                "tactic": tactic,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "description": description,
            }
        )
    matched.sort(key=lambda step: _tactic_rank(step["tactic"]))
    return matched


def enrich_item_attack(item: Dict) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    if enrichment.get("attack_chain"):
        return item

    text = f"{item.get('title') or ''} {item.get('description') or ''}".strip()
    if not text:
        return item
    enrichment["attack_chain"] = map_attack_chain(text)
    return item
