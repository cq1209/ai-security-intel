"""AI security filtering and tag-tree classification.

Aligned with member C's whitelist/blacklist and six-category tag tree.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# Whitelists
# ---------------------------------------------------------------------------

# Core AI subject terms (table 8).
AI_SUBJECT_KEYWORDS = (
    "ai",
    "人工智能",
    "大模型",
    "llm",
    "生成式ai",
    "aigc",
    "多模态",
    "机器学习",
    "深度学习",
    "神经网络",
    "智能体",
    "agent",
    "多智能体",
    "自主决策",
    "任务编排",
    "工具调用",
    "function calling",
    "模型",
    "推理",
    "训练",
    "微调",
    "预训练",
    "提示词",
    "prompt",
    "嵌入",
    "embedding",
    "向量",
    "知识库",
    "rag",
    "mcp",
    "模型上下文协议",
    "openai api",
    "api密钥",
    "插件",
    "工具链",
    # AI-specific attack concepts that inherently imply AI security.
    "提示注入",
    "越狱",
    "数据投毒",
    "模型窃取",
    "模型提取",
    "对抗样本",
    "系统提示泄漏",
    "prompt injection",
    "jailbreak",
    "data poisoning",
    "model theft",
    "model extraction",
    "adversarial example",
    "system prompt leakage",
    "artificial intelligence",
    "large language model",
    "large language models",
    "generative ai",
    "machine learning",
    "deep learning",
    "neural network",
    "multimodal",
    "foundation model",
    "model inference",
    "inference server",
    "knowledge base",
    "model context protocol",
    "api key",
)

# AI component / framework names (table 9).
COMPONENT_KEYWORDS = (
    "ollama",
    "vllm",
    "triton",
    "tgi",
    "sglang",
    "llama.cpp",
    "llamacpp",
    "llama-cpp",
    "openllm",
    "onnx",
    "onnx runtime",
    "onnxruntime",
    "tensorrt",
    "openvino",
    "pytorch",
    "tensorflow",
    "jax",
    "hugging face",
    "huggingface",
    "transformers",
    "peft",
    "lora",
    "deepspeed",
    "megatron",
    "langchain",
    "langgraph",
    "llama-index",
    "llamaindex",
    "autogen",
    "crewai",
    "dify",
    "coze",
    "n8n",
    "autogpt",
    "milvus",
    "faiss",
    "chroma",
    "chromadb",
    "weaviate",
    "pinecone",
    "qdrant",
    "elasticsearch",
    "neo4j",
    "cuda",
    "cudnn",
    "rocm",
    "docker",
    "kubernetes",
    "k8s",
    "ray",
    "kubeflow",
    "mlflow",
    "llama",
    "qwen",
    "deepseek",
    "chatglm",
    "baichuan",
    "mistral",
    "mixtral",
    "stable diffusion",
    "stable-diffusion",
    "comfyui",
    "gradio",
)

# Security risk terms (table 10).
SECURITY_RISK_KEYWORDS = (
    "漏洞",
    "vulnerability",
    "security",
    "advisory",
    "cve",
    "cnvd",
    "cnnvd",
    "0day",
    "nday",
    "补丁",
    "修复",
    "利用",
    "poc",
    "exp",
    "攻击",
    "入侵",
    "injection",
    "注入",
    "command injection",
    "os command injection",
    "code injection",
    "提示注入",
    "越狱",
    "系统提示泄漏",
    "prompt injection",
    "jailbreak",
    "system prompt leakage",
    "数据投毒",
    "data poisoning",
    "后门",
    "backdoor",
    "模型窃取",
    "model theft",
    "model extraction",
    "对抗样本",
    "adversarial example",
    "adversarial attack",
    "rce",
    "remote code execution",
    "arbitrary code execution",
    "code execution",
    "ssrf",
    "sql注入",
    "sql injection",
    "xss",
    "cross-site scripting",
    "csrf",
    "路径遍历",
    "path traversal",
    "反序列化",
    "deserialization",
    "buffer overflow",
    "heap overflow",
    "stack overflow",
    "use-after-free",
    "memory corruption",
    "dos",
    "拒绝服务",
    "denial of service",
    "out-of-bounds",
    "out of bounds",
    "out-of-bounds write",
    "权限提升",
    "privilege escalation",
    "越权",
    "authorization bypass",
    "authentication bypass",
    "improper authentication",
    "供应链",
    "supply chain",
    "依赖",
    "dependency",
    "权重",
    "weights",
    "数据集",
    "dataset",
    "镜像",
    "image",
    "容器逃逸",
    "container escape",
    "api密钥泄漏",
    "api key leak",
    "敏感信息",
    "sensitive information",
    "information disclosure",
    "directory traversal",
    "authorization",
    "improper authorization",
    "adversarial",
    "合规",
    "compliance",
    "政策",
    "policy",
    "标准",
    "standard",
    "法规",
    "regulation",
    "监管",
    "治理",
    "governance",
    "数据安全",
    "data security",
    "隐私",
    "privacy",
    "exploit",
    "fix",
    "patch",
    "arxiv",
    "whitepaper",
    "technical report",
    "research paper",
    "论文",
    "白皮书",
    "研究报告",
)


# ---------------------------------------------------------------------------
# Blacklists
# ---------------------------------------------------------------------------

# Completely exclude (table 13).
EXCLUDE_BLACKLIST = (
    "招聘",
    "求职",
    "实习",
    "校招",
    "社招",
    "兼职",
    "内推",
    "简历",
    "面试",
    "培训",
    "课程",
    "报名",
    "培训班",
    "训练营",
    "认证",
    "考试",
    "广告",
    "促销",
    "优惠",
    "折扣",
    "抽奖",
    "赞助",
    "招商",
    "营销",
    "带货",
    "峰会",
    "大会",
    "论坛",
    "直播",
    "沙龙",
    "参会",
    "明星",
    "娱乐",
    "八卦",
    "体育",
    "旅游",
    "美食",
    "情感",
    "养生",
    "股价",
    "财报",
    "融资",
    "投资",
    "股市",
    "基金",
    "房地产",
    "赌博",
    "彩票",
    "色情",
    "暴力",
    "诈骗",
)

# Downgrade / manual-review (table 14).
DOWNGRADE_BLACKLIST = (
    "产品发布",
    "发布会",
    "评测",
    "对比",
    "推荐",
    "排行榜",
    "最佳实践",
    "经验分享",
    "编程教程",
    "安装教程",
    "使用教程",
    "入门",
    "配置教程",
    "踩坑",
    "标题党",
    "转载",
    "聚合",
    "旧闻",
    "重复",
    "观点",
    "评论",
    "随笔",
    "杂谈",
    "猜测",
    "传闻",
)

# Backward-compatible aliases used by older collectors.
TEXT_KEYWORDS = AI_SUBJECT_KEYWORDS
BLACKLIST_KEYWORDS = EXCLUDE_BLACKLIST + DOWNGRADE_BLACKLIST


def _contains(text: str, keywords: Iterable[str]) -> bool:
    lowered = text.lower()
    for keyword in keywords:
        lowered_keyword = keyword.lower()
        if lowered_keyword.isascii():
            if re.search(
                r"(?<![a-z0-9])" + re.escape(lowered_keyword) + r"(?![a-z0-9])",
                lowered,
            ):
                return True
        elif lowered_keyword in lowered:
            return True
    return False


def matches_ai_subject(text: str) -> bool:
    return _contains(text, AI_SUBJECT_KEYWORDS)


def matches_component(text: str) -> bool:
    return _contains(text, COMPONENT_KEYWORDS)


def matches_security_risk(text: str) -> bool:
    return _contains(text, SECURITY_RISK_KEYWORDS)


def matches_exclude_blacklist(text: str) -> bool:
    return _contains(text, EXCLUDE_BLACKLIST)


def matches_downgrade_blacklist(text: str) -> bool:
    return _contains(text, DOWNGRADE_BLACKLIST)


def matches_ai_keywords(
    text: str,
    component_keywords: Optional[Iterable[str]] = None,
    text_keywords: Optional[Iterable[str]] = None,
    blacklist_keywords: Optional[Iterable[str]] = None,
) -> bool:
    """Return True when the item is AI security relevant.

    Rule: (core AI subject OR AI component) AND security-risk term, and not
    hard-excluded by the completely-exclude blacklist.
    """
    component_keywords = component_keywords or COMPONENT_KEYWORDS
    text_keywords = text_keywords or AI_SUBJECT_KEYWORDS
    blacklist_keywords = blacklist_keywords or EXCLUDE_BLACKLIST

    ai_hit = _contains(text, component_keywords) or _contains(text, text_keywords)
    risk_hit = matches_security_risk(text)
    excluded = _contains(text, blacklist_keywords)

    if excluded and not (ai_hit and risk_hit):
        return False
    return ai_hit and risk_hit


def is_security_related(text: str) -> bool:
    return matches_security_risk(text)


# ---------------------------------------------------------------------------
# Tag-tree classification (six first-level categories)
# ---------------------------------------------------------------------------

# L2 tag -> keyword set, grouped by first-level category in A > B > ... order.
_L2_RULES: Dict[str, tuple] = {
    "A1": (
        "ollama", "vllm", "triton", "tgi", "sglang", "llama.cpp", "llamacpp",
        "openllm", "onnx runtime", "onnxruntime", "tensorrt", "openvino",
    ),
    "A2": (
        "pytorch", "tensorflow", "jax", "hugging face", "huggingface",
        "transformers", "peft", "lora", "deepspeed", "megatron",
    ),
    "A3": (
        "milvus", "faiss", "chroma", "chromadb", "weaviate", "pinecone",
        "qdrant", "elasticsearch", "neo4j",
    ),
    "A4": (
        "langchain", "langgraph", "llama-index", "llamaindex", "autogen",
        "crewai", "dify", "coze", "n8n", "mcp",
    ),
    "A5": (
        "cuda", "cudnn", "rocm", "docker", "kubernetes", "k8s", "ray",
        "kubeflow", "mlflow",
    ),
    "B1": (
        "prompt injection", "jailbreak", "提示注入", "越狱", "系统提示泄漏",
        "role bypass", "encoding bypass",
    ),
    "B2": ("data poisoning", "backdoor", "数据投毒", "投毒", "后门", "训练数据", "poisoning"),
    "B3": (
        "model theft", "model extraction", "adversarial example", "membership inference",
        "evasion attack", "模型窃取", "模型提取", "对抗样本", "成员推理", "逃逸攻击",
    ),
    "B4": ("privacy", "compliance", "gdpr", "copyright", "隐私", "合规", "数据安全", "敏感信息", "版权"),
    "C1": (
        "tool call", "code interpreter escape",
        "工具调用", "越权", "mcp", "插件", "代码解释器逃逸",
    ),
    "C2": ("rag poisoning", "retrieval injection", "citation forgery", "rag投毒", "知识库污染", "检索注入", "引用伪造"),
    "C3": ("web vulnerability", "api key leak", "prompt leak", "web漏洞", "api密钥泄漏", "提示词泄漏", "权限控制"),
    "C4": ("goal hijacking", "multi-agent", "resource abuse", "目标劫持", "规划失控", "多智能体串谋", "资源滥用"),
    "D1": ("dependency", "python package", "npm package", "依赖库", "python包", "npm包", "开源组件"),
    "D2": ("model weights", "dataset", "malicious model", "模型权重", "数据集", "恶意模型", "投毒数据集"),
    "D3": ("image poisoning", "container escape", "ci/cd", "镜像投毒", "容器逃逸", "基础镜像"),
    "D4": ("third-party api", "cloud service", "第三方api", "云服务", "插件市场"),
    "E1": ("policy", "regulation", "algorithm governance", "政策", "法规", "监管", "算法治理"),
    "E2": ("standard", "iso", "nist", "owasp", "标准"),
    "E3": ("arxiv", "paper", "conference paper", "论文", "会议论文", "技术报告"),
    "E4": ("whitepaper", "vendor report", "白皮书", "厂商报告", "咨询报告", "行业报告"),
}

_L2_TO_L1 = {
    "A1": "A", "A2": "A", "A3": "A", "A4": "A", "A5": "A",
    "B1": "B", "B2": "B", "B3": "B", "B4": "B",
    "C1": "C", "C2": "C", "C3": "C", "C4": "C",
    "D1": "D", "D2": "D", "D3": "D", "D4": "D",
    "E1": "E", "E2": "E", "E3": "E", "E4": "E",
}

_L1_NAMES = {
    "A": "AI基础设施与框架风险",
    "B": "模型与数据安全风险",
    "C": "AI应用与智能体风险",
    "D": "AI供应链风险",
    "E": "AI安全政策与标准",
    "F": "通用安全情报",
}


def classify_tag(text: str) -> Optional[str]:
    """Return the L2 tag (e.g. ``A1``) or ``None`` when it cannot be classified."""
    # Supply-chain / artifact signals take priority over component names.
    if any(
        keyword in text.lower()
        for keyword in ("supply chain", "third-party", "third party", "model weights", "malicious model")
    ):
        for l2 in ("D2", "D1"):
            if _contains(text, _L2_RULES[l2]):
                return l2
    if any(keyword in text.lower() for keyword in ("container", "image poisoning", "镜像", "容器")):
        for l2 in ("D3",):
            if _contains(text, _L2_RULES[l2]):
                return l2

    for l2, keywords in _L2_RULES.items():
        if _contains(text, keywords):
            return l2
    return None


def tag_category(text: str) -> Optional[str]:
    """Return the first-level category (``A``-``F``) for a piece of text."""
    l2 = classify_tag(text)
    if l2:
        return _L2_TO_L1[l2]
    if matches_security_risk(text) and not (
        matches_ai_subject(text) or matches_component(text)
    ):
        return "F"
    return None


def build_tags(text: str) -> List[str]:
    """Build a stable tag list for structured intelligence."""
    tags: List[str] = []
    l2 = classify_tag(text)
    if l2:
        tags.append(l2)
        tags.append(_L2_TO_L1[l2])
        tags.append(_L1_NAMES[_L2_TO_L1[l2]])
    elif matches_security_risk(text):
        tags.append("F")
        tags.append(_L1_NAMES["F"])
    for keyword in COMPONENT_KEYWORDS:
        if _contains(text, [keyword]):
            tags.append(keyword.lower())
            break
    return tags


# ---------------------------------------------------------------------------
# NVD-specific helpers
# ---------------------------------------------------------------------------

def cpe_strings(cve: Dict) -> List[str]:
    strings: List[str] = []
    for affected in cve.get("affected", []) or []:
        for item in affected.get("affectedData", []) or []:
            vendor = item.get("vendor") or ""
            product = item.get("product") or ""
            package_url = item.get("packageURL") or ""
            if vendor:
                strings.append(vendor)
            if product:
                strings.append(product)
            if package_url:
                strings.append(package_url)
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
    text_keywords = text_keywords or AI_SUBJECT_KEYWORDS
    blacklist_keywords = blacklist_keywords or EXCLUDE_BLACKLIST

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
