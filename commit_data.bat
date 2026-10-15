@echo off
cd /d "D:\Codex\2026-09-26\new-chat\ai-security-intel"
git add data/output/*.jsonl data/output/*.json
git commit -m "chore: update intelligence data snapshot"
git push
