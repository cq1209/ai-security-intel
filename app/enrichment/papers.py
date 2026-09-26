"""Related paper enrichment via arXiv search and semantic similarity."""
from __future__ import annotations

import logging
import math
import re
from typing import Dict, List, Sequence

import feedparser
import httpx

logger = logging.getLogger(__name__)

ARXIV_API_URL = "https://export.arxiv.org/api/query"
MODEL_NAME = "all-MiniLM-L6-v2"

_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "into", "via", "using",
    "what", "when", "where", "which", "your", "its", "can", "has", "have",
    "are", "was", "were", "not", "but", "all", "any", "may", "will", "their",
    "because", "about", "between", "through", "during", "without", "within",
    "a", "an", "of", "to", "in", "on", "at", "by", "or", "as", "is", "be",
}

_encoder = None
_encoder_failed = False


def _get_encoder():
    global _encoder, _encoder_failed
    if _encoder is None and not _encoder_failed:
        try:
            from sentence_transformers import SentenceTransformer

            _encoder = SentenceTransformer(MODEL_NAME)
        except Exception as exc:  # pragma: no cover - depends on local model cache
            logger.warning(
                "SentenceTransformer unavailable, falling back to lexical similarity: %s",
                exc,
            )
            _encoder_failed = True
    return _encoder


def _normalize(text: str) -> List[str]:
    return [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9._-]{2,}", text or "")]


def _character_ngrams(tokens: Sequence[str], size: int = 3) -> set:
    grams: set = set()
    for token in tokens:
        if len(token) >= size:
            grams.update(token[i : i + size] for i in range(len(token) - size + 1))
    return grams


def _lexical_similarity(left: str, right: str) -> float:
    left_tokens = set(_normalize(left))
    right_tokens = set(_normalize(right))
    if not left_tokens or not right_tokens:
        return 0.0
    left_grams = _character_ngrams(left_tokens)
    right_grams = _character_ngrams(right_tokens)
    if left_grams and right_grams:
        return len(left_grams & right_grams) / max(len(left_grams | right_grams), 1)
    return len(left_tokens & right_tokens) / max(len(left_tokens | right_tokens), 1)


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def _semantic_similarity(texts: Sequence[str], query: str) -> List[float]:
    encoder = _get_encoder()
    if encoder is None:
        return [_lexical_similarity(query, text) for text in texts]
    try:
        query_embedding = encoder.encode(query, normalize_embeddings=True)
        embeddings = encoder.encode(list(texts), normalize_embeddings=True)
        return [float(max(0.0, _cosine(query_embedding, embedding))) for embedding in embeddings]
    except Exception as exc:  # pragma: no cover - runtime model failure
        logger.warning("Semantic embedding failed, using lexical similarity: %s", exc)
        return [_lexical_similarity(query, text) for text in texts]


def _extract_search_terms(item: Dict, limit: int = 4) -> List[str]:
    intel_id = str(item.get("intel_id") or "")
    text = f"{item.get('title') or ''} {item.get('description') or ''}"
    terms: List[str] = []
    seen: set = set()
    if re.match(r"^CVE-\d{4}-\d+$", intel_id, re.IGNORECASE):
        terms.append(intel_id.upper())
        seen.add(intel_id.lower())
    for token in re.findall(r"[A-Za-z][A-Za-z0-9._+-]{2,}", text):
        lowered = token.lower()
        if lowered in seen or lowered in _STOPWORDS or re.fullmatch(r"\d+", token):
            continue
        seen.add(lowered)
        terms.append(token)
    terms.sort(key=lambda token: (not any(char.isdigit() for char in token), -len(token)))
    return terms[:limit]


def _build_query(terms: List[str]) -> str:
    if not terms:
        return "cat:cs.CR OR cat:cs.AI"
    clauses = [f'all:"{term}"' for term in terms]
    return " OR ".join(clauses)


def search_related_papers(item: Dict, limit: int = 10) -> List[Dict]:
    query = _build_query(_extract_search_terms(item))
    with httpx.Client(timeout=30) as client:
        response = client.get(
            ARXIV_API_URL,
            params={
                "search_query": query,
                "start": 0,
                "max_results": min(max(limit, 1), 30),
                "sortBy": "relevance",
                "sortOrder": "descending",
            },
            headers={"User-Agent": "ai-security-intel/0.1", "Accept": "application/atom+xml"},
        )
        response.raise_for_status()
    entries = feedparser.parse(response.content).entries

    papers: List[Dict] = []
    for entry in entries:
        authors = [author.get("name") for author in entry.get("authors", []) if author.get("name")]
        papers.append(
            {
                "title": re.sub(r"\s+", " ", entry.get("title") or "").strip(),
                "arxiv_id": entry.get("id") or entry.get("link"),
                "authors": authors,
                "abstract": re.sub(r"\s+", " ", entry.get("summary") or "").strip(),
            }
        )
    return papers


def enrich_item_papers(item: Dict, limit: int = 3) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    if enrichment.get("related_papers"):
        return item

    query_text = f"{item.get('title') or ''} {item.get('description') or ''}".strip()
    if not query_text:
        return item

    try:
        papers = search_related_papers(item, limit=max(limit * 3, 5))
    except Exception as exc:
        logger.info("Related paper search failed for %s: %s", item.get("intel_id"), exc)
        return item

    if not papers:
        return item

    texts = [f"{paper['title']} {paper['abstract']}" for paper in papers]
    scores = _semantic_similarity(texts, query_text)
    ranked = sorted(zip(papers, scores), key=lambda pair: pair[1], reverse=True)

    related: List[Dict] = []
    for paper, score in ranked[:limit]:
        if score <= 0.0:
            continue
        related.append(
            {
                "title": paper["title"],
                "arxiv_id": paper["arxiv_id"],
                "authors": paper["authors"][:5],
                "abstract": paper["abstract"],
                "similarity_score": round(score, 4),
            }
        )
    enrichment["related_papers"] = related
    return item
