"""Sanitizer: OSINT tool output is untrusted data, never instructions.

Everything a tool returns (HTML titles, WHOIS/TXT records, code snippets, banners...)
came from the public internet and could contain text crafted to look like
instructions to the planner LLM ("ignore previous instructions", fake `system:`
turns, etc). Per brief section 6.3, every such string is truncated, stripped of
role/instruction-mimicking sequences, and wrapped in `<untrusted_data>` delimiters
before it's ever placed in the planner's context.

This is defense in depth, not the only defense: even if a pattern here misses a novel
phrasing and the planner "reads" it as an instruction, the actual security boundary is
enforced in code — Scope Guard and the phase/tool allowlist in `tool_router.py` decide
what's actually allowed to run, regardless of what the LLM asks for.
"""

from __future__ import annotations

import re

DEFAULT_MAX_LEN = 500

# Role markers and common jailbreak/override phrasings, case-insensitive. Matched
# fragments are replaced with a neutral marker, not deleted, so the redaction itself
# doesn't create new exploitable ambiguity.
_ROLE_MARKER_RE = re.compile(
    r"(^|\n|[<>.!?]\s*)\s*(system|assistant|user|tool)\s*:", re.IGNORECASE
)
_OVERRIDE_PHRASES_RE = re.compile(
    r"ignor[ae]\s+(all\s+|previous\s+|prior\s+)*(the\s+)?(previous\s+|prior\s+)?instructions"
    r"|ignora\s+(todas\s+)?las\s+instrucciones\s+(anteriores|previas)"
    r"|disregard\s+(all\s+|previous\s+)*(the\s+)?(previous\s+)?instructions"
    r"|new\s+instructions\s*:"
    r"|you\s+are\s+now\s+"
    r"|system\s+override"
    r"|(important\s+)?system\s+message\s*:"
    r"|do\s+anything\s+now"
    r"|reveal\s+your\s+(system\s+prompt|api\s+key)"
    r"|print\s+your\s+(system\s+)?prompt",
    re.IGNORECASE,
)
_CODE_FENCE_RE = re.compile(r"```")
_ZERO_WIDTH_RE = re.compile(r"[​‌‍﻿]")


def sanitize(text: str, *, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Neutralize instruction-like content and truncate. Does NOT add delimiters —
    use `wrap_untrusted` for that once the value is embedded in planner context."""
    if not text:
        return text

    cleaned = _ZERO_WIDTH_RE.sub("", text)
    cleaned = _ROLE_MARKER_RE.sub(r"\1[filtered-role-marker]:", cleaned)
    cleaned = _OVERRIDE_PHRASES_RE.sub("[filtered-instruction-override]", cleaned)
    cleaned = _CODE_FENCE_RE.sub("'''", cleaned)

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...[truncated]"
    return cleaned


def wrap_untrusted(text: str, *, source: str) -> str:
    """Wrap already-sanitized text in explicit untrusted-data delimiters."""
    return f'<untrusted_data source="{source}">\n{text}\n</untrusted_data>'


def sanitize_and_wrap(text: str, *, source: str, max_len: int = DEFAULT_MAX_LEN) -> str:
    return wrap_untrusted(sanitize(text, max_len=max_len), source=source)
