"""Minimal starter sanitizer. Extend it and write security tests before AI calls."""
import re

def sanitize(text: str) -> str:
    return re.sub(r"(?i)(password|api_key|token)=\S+", r"\1=[REDACTED]", text)
