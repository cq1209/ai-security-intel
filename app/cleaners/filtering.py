"""AI security keyword filtering."""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

# 组件/框架名称，用于在 CPE 或描述中识别 AI 项目。
COMPONENT_KEYWORDS = (
    "tensorflow",
    "pytorch",
    "torchserve",
    "ollama",
    "vllm",
    "huggingface",
    "transformers",
    "langchain",
    "llama.cpp",
    "llamacpp",
    "onnxruntime",
    "onnx",
    "deepspeed",
    "triton inference server",
    "kubeflow",
    "mlflow",
    "ray",
)

# 出现在标题或描述中的 AI 安全相关词。
TEXT_KEYWORDS = (
    "large language model",
    "llm",
    "prompt injection",
    "model poisoning",
    "adversarial attack",
    "machine learning",
    "neural network",
    "retrieval augmented generation",
    "rag pipeline",
    "embedding model",
    "generative ai",
)

# 明确属于普通 Web 漏洞的词，命中则排除，降低误报。
BLACKLIST_KEYWORDS = (
    "wordpress",
    "sql injection",
    "cross-site scripting",
    "csrf",
    "php",
    "javascript",
    "python social auth",
    "social auth",
    "open redirect",
)


def _contains(text: str, keywords: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def matches_ai_keywords(
    text: str,
    component_keywords: Optional[Iterable[str]] = None,
    text_keywords: Optional[Iterable[str]] = None,
    blacklist_keywords: Optional[Iterable[str]] = None,
) -> bool:
    component_keywords = component_keywords or COMPONENT_KEYWORDS
    text_keywords = text_keywords or TEXT_KEYWORDS
    blacklist_keywords = blacklist_keywords or BLACKLIST_KEYWORDS

    lowered = text.lower()
    component_hit = any(keyword in lowered for keyword in component_keywords)
    text_hit = any(keyword in lowered for keyword in text_keywords)
    blacklisted = any(keyword in lowered for keyword in blacklist_keywords)
    return (component_hit or text_hit) and not blacklisted


def cpe_strings(cve: Dict) -> List[str]:
    strings: List[str] = []
    for node in cve.get("configurations", []) or []:
        for match in node.get("nodes", []) or []:
            for cpe in match.get("cpeMatch", []) or []:
                criteria = cpe.get("criteria")
                if criteria:
                    strings.append(criteria)
    return strings


def description(cve: Dict) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def is_ai_relevant(
    cve: Dict,
    component_keywords: Optional[Iterable[str]] = None,
    text_keywords: Optional[Iterable[str]] = None,
    blacklist_keywords: Optional[Iterable[str]] = None,
) -> bool:
    component_keywords = component_keywords or COMPONENT_KEYWORDS
    text_keywords = text_keywords or TEXT_KEYWORDS
    blacklist_keywords = blacklist_keywords or BLACKLIST_KEYWORDS

    cpes = " ".join(cpe_strings(cve)).lower()
    text = description(cve)
    title = str(cve.get("id") or "").lower()
    haystack = f"{title} {text}".lower()

    return matches_ai_keywords(
        f"{cpes} {haystack}",
        component_keywords=component_keywords,
        text_keywords=text_keywords,
        blacklist_keywords=blacklist_keywords,
    )
