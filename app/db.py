"""MongoDB connection helpers."""
from __future__ import annotations

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from app.config import MONGO_DB, MONGO_URI

_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client


def get_db() -> Database:
    return get_client()[MONGO_DB]


def raw_collection() -> Collection:
    return get_db()["raw_intel"]


def structured_collection() -> Collection:
    return get_db()["structured_intel"]


def enriched_collection() -> Collection:
    return get_db()["enriched_intel"]
