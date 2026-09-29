"""Secret redaction for everything the tool records or writes (section 15).

Evidence and diagnostics can quote input content: a duplicated row key, a
malformed value, an exception message. If an input or the environment holds a
credential, quoting it would copy that credential into run directories that
are meant to be shared. Values that look like secrets are therefore replaced
with :data:`REDACTED` at the point where evidence is *recorded*, before it is
hashed into the ledger. Redacting later, when files are written, would either
leave the secret in hashed content or break the hash chain.

Two detectors are combined:

* **Shape patterns** for well-known credential formats (private-key blocks,
  provider token prefixes, JWTs, ``password=...`` assignments).
* **Environment values**: the current value of every environment variable
  whose *name* says it holds a secret (``*TOKEN*``, ``*SECRET*``, ...). This
  catches credentials of any shape, as long as the process can see them.

Redaction is deliberately over-eager. A false positive hides one value from a
report; a false negative leaks a credential.
"""

from __future__ import annotations

import os
import re
from typing import Any, Mapping

__all__ = ["REDACTED", "redact_text", "redact"]

REDACTED = "[REDACTED]"

#: Shorter environment values are too likely to occur by accident in ordinary
#: text (``"1"``, ``"true"``) to be redacted verbatim.
_MIN_ENV_SECRET_LENGTH = 8

_SECRET_ENV_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH",
    re.IGNORECASE,
)

_SHAPES = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
)

#: ``password = hunter2``-style assignments keep their label and lose their value.
_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|token)"
    r"(\s*[:=]\s*)([^\s,;\"']{6,})"
)


def _environment_secrets() -> list[str]:
    """Current values of secret-named environment variables, longest first.

    Longest first so that a secret containing another secret is replaced as a
    whole rather than leaving a recognizable remainder.
    """
    values = {
        value
        for name, value in os.environ.items()
        if _SECRET_ENV_NAME.search(name) and len(value) >= _MIN_ENV_SECRET_LENGTH
    }
    return sorted(values, key=lambda value: (-len(value), value))


def redact_text(text: str) -> str:
    """Return ``text`` with every secret-looking value replaced by :data:`REDACTED`."""
    for secret in _environment_secrets():
        text = text.replace(secret, REDACTED)
    for pattern in _SHAPES:
        text = pattern.sub(REDACTED, text)
    return _ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)


def redact(value: Any) -> Any:
    """Recursively redact the strings inside a JSON-like value.

    Mapping keys are redacted too: a column name or record key is quoted text
    like any other. Non-string leaves are returned unchanged.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {redact_text(key) if isinstance(key, str) else key: redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return frozenset(redact(item) for item in value)
    return value
