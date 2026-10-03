"""Labeled evaluation cases for filtering and tag-classification accuracy."""
from __future__ import annotations

# (text, expected_ai_relevant, expected_l1)
EVAL_CASES = [
    # --- AI security: A infrastructure ---
    ("Ollama has a remote code execution vulnerability", True, "A"),
    ("vLLM allows privilege escalation before 0.29.0", True, "A"),
    ("Triton inference server denial of service", True, "A"),
    ("llama.cpp buffer overflow in GGUF parsing", True, "A"),
    ("ONNX Runtime memory corruption vulnerability", True, "A"),
    ("PyTorch use-after-free in autograd", True, "A"),
    ("TensorFlow out-of-bounds write", True, "A"),
    ("Hugging Face Transformers path traversal", True, "A"),
    ("DeepSpeed command injection", True, "A"),
    ("MLflow remote code execution", True, "A"),
    ("Milvus information disclosure", True, "A"),
    ("Chroma path traversal vulnerability", True, "A"),
    ("Ray privilege escalation", True, "A"),
    ("LangChain tool call privilege escalation", True, "A"),
    ("LangGraph prompt injection", True, "A"),
    ("LlamaIndex SQL injection", True, "A"),
    ("AutoGen arbitrary code execution", True, "A"),
    ("CrewAI SSRF vulnerability", True, "A"),
    ("Dify authentication bypass", True, "A"),
    # --- AI security: B model/data ---
    ("Prompt injection leaks the system prompt", True, "B"),
    ("Jailbreak bypasses model safety constraints", True, "B"),
    ("Training data poisoning backdoor attack", True, "B"),
    ("Model theft via adversarial examples", True, "B"),
    ("Model extraction attack on LLM", True, "B"),
    # --- AI security: D supply chain ---
    ("PyTorch dependency supply chain vulnerability", True, "D"),
    ("Malicious model weights on Hugging Face", True, "D"),
    ("Container image poisoning in AI deployment", True, "D"),
    # --- AI security: E policy/standard ---
    ("NIST publishes an AI security standard", True, "E"),
    ("arXiv paper on adversarial machine learning", True, "E"),
    ("AI regulation policy announcement", True, "E"),
    # --- generic security: F ---
    ("DrayTek router command injection vulnerability", False, "F"),
    ("Adobe Acrobat buffer overflow", False, "F"),
    ("Microsoft Windows privilege escalation", False, "F"),
    ("SolarWinds deserialization vulnerability", False, "F"),
    ("Fortinet improper authorization", False, "F"),
    ("WordPress plugin SQL injection", False, "F"),
    ("Nagios XI remote code execution", False, "F"),
    ("QNAP path traversal", False, "F"),
    ("Trend Micro directory traversal", False, "F"),
    ("ownCloud authentication bypass", False, "F"),
    # --- excluded: non-security ---
    ("Ollama usage tutorial", False, None),
    ("AI model evaluation ranking", False, None),
    ("AI engineer recruitment posting", False, None),
    ("Product launch announcement", False, None),
    ("Machine learning training course", False, None),
    ("Programming tutorial for beginners", False, None),
    ("Stock market investment news", False, None),
]
