#!/usr/bin/env python3
"""
Content PR Reviewer!!!
Internal Documentation:
https://github.com/americanexpress/my-repo/blob/main/.github/content_pr_reviewer_readme.md

NOTE:
Update the README first before modifying validation logic in this file.											   																		
"""

from __future__ import annotations

import difflib
import json
import os
import re
import sys
import time
from base64 import b64decode
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from github import Auth, Github, GithubException
from github.GithubException import UnknownObjectException

try:
    import spacy

    try:
        NLP = spacy.load("en_core_web_sm")
    except Exception:
        NLP = None
except Exception:
    NLP = None


# =============================================================================
# Config
# =============================================================================
@dataclass(frozen=True)
class BotConfig:
    event_path: str
    token: str
    repository: str
    server_url: str
    api_url: str
    event_name: str
    actor: str = "github-actions[bot]"
    quiet_period_minutes: int = 60

    pending_label: str = "bot-review-pending"
    approved_label: str = "bot review completed"
    correction_label: str = "Needs Corrections :toolbox:"
    content_label:str="Content :book:" # #F910A0
    manual_review_label="For manual review :book:" ##6BFBFB


    @classmethod
    def from_env(cls) -> "BotConfig":
        event_path = os.environ.get("GITHUB_EVENT_PATH") or ""
        token = os.environ.get("GITHUB_TOKEN") or ""
        repository = os.environ.get("GITHUB_REPOSITORY") or ""
        server_url = os.environ.get("GITHUB_SERVER_URL") or ""
        api_url = os.environ.get("GITHUB_API_URL") or ""
        event_name = os.environ.get("GITHUB_EVENT_NAME") or ""
        actor = os.environ.get("GITHUB_ACTOR") or "github-actions[bot]"
        quiet_period_minutes = int(os.environ.get("QUIET_PERIOD_MINUTES", "60"))

        if not (event_path and token and repository):
            print("Missing required environment variables: GITHUB_EVENT_PATH, GITHUB_TOKEN, GITHUB_REPOSITORY")
            sys.exit(1)

        return cls(
            event_path=event_path,
            token=token,
            repository=repository,
            server_url=server_url,
            api_url=api_url,
            event_name=event_name,
            actor=actor,
            quiet_period_minutes=quiet_period_minutes,
        )


# =============================================================================
# Utility helpers
# =============================================================================
MONTH_PATTERN = re.compile(r"\b([A-Za-z]{3,20})\s+([0-9]{1,2}),\s+([0-9]{4})\b", flags=re.UNICODE)
SINGLE_DIGIT_RE = re.compile(r"(?<![A-Za-z0-9.])([0-9])(?![A-Za-z0-9.])")
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
DASH_WITH_SPACE_RE = re.compile(r"\s[–—]\s")
DASH_NO_SPACE_RE = re.compile(r"(?<!\s)[–—](?!\s)")
UNESCAPED_QUOTE_RE = re.compile(r'(?<!\\)"')
BROKEN_TAG_RE = re.compile(r"<[A-Za-z][^>]*<[^>]*>")
HTML_VOID_TAGS = {
    "br", "hr", "img", "input", "meta", "link", "area", "base", "col",
    "embed", "source", "track", "wbr",
}

DESCRIPTION_KEYS_DIGITS = {"description", "short description", "short_description"}
DESCRIPTION_KEYS_TEXT = {
    "description", "short description", "short_description", "bullettext",
    "furtherdescription", "itemdescription", "heading",
}

DIGIT_WORDS = {str(i): word for i, word in enumerate([
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"
])}

AMEX_VARIANTS_RE = re.compile(r"\b(amex|amx|axp)\b", re.IGNORECASE)
AED_RE = re.compile(r"\bAED\b", re.IGNORECASE)

NOT_POSSESSIVE = r"(?![’']s\b)"

HYPHENATION_UNITS = {
    "digit", "day", "week", "month", "year",
    "hour", "minute", "second", "bit", "star",
    "page", "line", "step", "pack",
}

IGNORE_DIGIT_CONTEXTS = (
    re.compile(r"(?i)\bstep\s+[0-9]+\b"),
    re.compile(r"(?i)\bpoint\s+[0-9]+\b"),
    re.compile(r"(?i)\bitem\s+[0-9]+\b"),
    re.compile(r"(?i)\b[0-9]+-legged\b"),
    re.compile(r"(?i)\b[0-9]+-step\b"),
    re.compile(r"(?i)\b[0-9]+-year-old\b"),
    re.compile(r"(?i)\b(?:address\s+line|partner|line|item|step|section|page|chapter|row|column|part|token|version|question)\s+\d+\b"),
    re.compile(r"(?i)\b(?:\d+[:\-]\d+|[a-z]+-\d+|\d+-[a-z]+)\b"),
    re.compile(r"(?:(?<=[^\w\s])\d+|\d+(?=[^\w\s]))"),
    re.compile(r"(?i)\b\d+\s*\([^)]*\)"),
    re.compile(r"(?i)\b\d+\s*=\s*[^,)\n]+"),
    re.compile(r"(?i)\b\d+\s*-\s*\d+\b"),
    re.compile(r"(?i)\b(?:range|scale)\s+(?:from\s+)?\d+\s*(?:to|-)\s*\d+\b"),
)

CAPITALIZATION_RULES = [
    {
        "term": "Merchant",
        "regex": re.compile(rf"\bMerchant\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Merchant" exactly as shown in this instruction.',
        "suggested_fix": "Merchant",
        "allow_sentence_start": True,
    },
    {
        "term": "Customer",
        "regex": re.compile(rf"\bCustomer\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Customer" exactly as shown in this instruction.',
        "suggested_fix": "Customer",
        "allow_sentence_start": True,
    },
    {
        "term": "Card Number",
        "regex": re.compile(rf"\bCard\s+Number\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Card Number" exactly as shown in this instruction.',
        "suggested_fix": "Card Number",
        "allow_sentence_start": True,
    },
    {
        "term": "The Partner",
        "regex": re.compile(r"(?:(?<=^)|(?<=[.!?]\s))the\s+partner\b", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "The Partner" exactly as shown in this instruction.',
        "suggested_fix": "The Partner",
        "allow_sentence_start": False,
    },
    {
        "term": "the Partner",
        "regex": re.compile(r"(?<!^)(?<![.!?]\s)the\s+partner\b", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Partner" exactly as shown in this instruction.',
        "suggested_fix": "Partner",
        "allow_sentence_start": False,
    },
    {
        "term": "Card Member",
        "regex": re.compile(rf"\bCard\s+Member\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Card Member" exactly as shown in this instruction.',
        "suggested_fix": "Card Member",
        "allow_sentence_start": True,
    },
    {
        "term": "Buyer",
        "regex": re.compile(rf"\bBuyer\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Buyer" exactly as shown in this instruction.',
        "suggested_fix": "Buyer",
        "allow_sentence_start": True,
    },
    {
        "term": "Seller",
        "regex": re.compile(rf"\bSeller\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "Seller" exactly as shown in this instruction.',
        "suggested_fix": "Seller",
        "allow_sentence_start": True,
    },
    {
        "term": "OAuth",
        "regex": re.compile(rf"\bOAuth\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "OAuth" exactly as shown in this instruction.',
        "suggested_fix": "OAuth",
        "allow_sentence_start": False,
    },
    {
        "term": "HMAC",
        "regex": re.compile(rf"\bHMAC\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "HMAC" exactly as shown in this instruction.',
        "suggested_fix": "HMAC",
        "allow_sentence_start": False,
    },
    {
        "term": "ZIP Code",
        "regex": re.compile(rf"\bZIP\s+Code\b{NOT_POSSESSIVE}", re.IGNORECASE),
        "fields": DESCRIPTION_KEYS_TEXT,
        "message": 'Always capitalize "ZIP Code" exactly as shown in this instruction.',
        "suggested_fix": "ZIP Code",
        "allow_sentence_start": False,
    },
]

PHRASE_NORMALIZATION_RULES = [
    {
        # Matches: 2-way, 2 way, two-way, two way
        "pattern": re.compile(r"\b(?:2|two)(?:\s*-\s*|\s+)way\b", re.IGNORECASE),
        "replacement": "two-way",
        "message": "Use {suggested} for consistency.",
        # If the phrase is followed by SSL/certificate, always title-case it.
        "force_title_case_if_followed_by": [
            re.compile(r"^\s*(?:ssl|certificates?)\b", re.IGNORECASE),
        ],
    },
]

SENSITIVE_FIELD_RULES = {
    "password": {
        "key_re": re.compile(r"(?i)password"),
        "hint_re": re.compile(r"(?i)password"),
        "allowed": {"******", "######", "NONE"},
        "message": "Password example must be masked. Use ******, ######, or NONE.",
        "suggested_fix": "******",
    },
    "first_name": {
        "key_re": re.compile(r"(?i)first[_\s-]*name"),
        "hint_re": re.compile(r"(?i)first[_\s-]*name"),
        "allowed": {"Adam", "Alice", "Bob", "Betty", "John", "Jane"},
        "message": "First Name example must be one of Adam, Alice, Bob, Betty, John, or Jane.",
        "suggested_fix": "Adam",
    },
    "last_name": {
        "key_re": re.compile(r"(?i)last[_\s-]*name"),
        "hint_re": re.compile(r"(?i)last[_\s-]*name"),
        "allowed": {"Smith", "Terry", "Underhill", "Jones"},
        "message": "Last Name example must be one of Smith, Terry, Underhill, or Jones.",
        "suggested_fix": "Smith",
    },
    "business_name": {
        "key_re": re.compile(r"(?i)business[_\s-]*name"),
        "hint_re": re.compile(r"(?i)business[_\s-]*name"),
        "allowed": {"American Express"},
        "message": "Business Name example must be American Express.",
        "suggested_fix": "American Express",
    },
    "email": {
        "key_re": re.compile(r"(?i)email"),
        "hint_re": re.compile(r"(?i)email"),
        "allowed": {"someone@example.com"},
        "message": "Email example must be someone@example.com.",
        "suggested_fix": "someone@example.com",
    },
    "address_line_1": {
        "key_re": re.compile(r"(?i)address[_\s-]*line[_\s-]*1"),
        "hint_re": re.compile(r"(?i)address[_\s-]*line[_\s-]*1"),
        "allowed": {"100 Elm Street", "200 Oak Street", "300 Juniper Lane", "400 Maple Court"},
        "message": "Address 1 example must be one of 100 Elm Street, 200 Oak Street, 300 Juniper Lane, or 400 Maple Court",
        "suggested_fix": "100 Elm Street",
    },
    "address_line_2": {
        "key_re": re.compile(r"(?i)address[_\s-]*line[_\s-]*2"),
        "hint_re": re.compile(r"(?i)address[_\s-]*line[_\s-]*3"),
        "allowed": {"Suite A", "Suite B"},
        "message": "Address 2 example must be one of Suite A or Suite B",
        "suggested_fix": "Suite A",
    },
    "card_number": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*card[_\s-]*number).*card[_\s-]*number"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*card[_\s-]*number).*card[_\s-]*number"),
        "allowed": {"122000000000003", "371270025401043", "372288864061024", "372322665813026", "374200000000004", "378247981763007"},
        "message": "Card Number example must be one of 122000000000003, 371270025401043, 372288864061024, 372322665813026, 374200000000004, 378247981763007",
        "suggested_fix": "122000000000003",
    },
    "ssn": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*ssn).*ssn[_\s-]*"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*ssn).*ssn[_\s-]*"),
        "allowed": {"123-45-6789", "078-05-1120", "219-09-9999", "123-12-1234", "111-11-1111", "222-22-2222","333-33-3333", "444-44-4444", "555-55-555"},
        "message": "SSN example must be one of 123-45-6789, 078-05-1120, 219-09-9999, 123-12-1234, 111-11-1111, 222-22-2222, 333-33-3333, 444-44-4444, 555-55-555",
        "suggested_fix": "219-09-9999",
    },
   "iban": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*iban[_\s-]*).*iban[_\s-]*"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*iban[_\s-]*).*iban[_\s-]*"),
        "allowed": {"00000000", "11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777", "88888888", "99999999"},
        "message": "IBAN example must be one of 00000000, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999",
        "suggested_fix": "00000000",
    },
    "access_token": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*access[_\s-]*token).*access[_\s-]*token"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*access[_\s-]*token).*access[_\s-]*token"),
        "allowed": {"00000000-d8v7-262f-33ot-9vh35dsj8x8m", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        "message": "Access Token example must be one of 00000000-d8v7-262f-33ot-9vh35dsj8x8m, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "suggested_fix": "00000000",
    },
    "refresh_token": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*refresh[_\s-]*token).*refresh[_\s-]*token"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*refresh[_\s-]*token).*refresh[_\s-]*token"),
        "allowed": {"00000000-cfe6-495d-98cc-7fb1be768a3d", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
        "message": "Refresh Token example must be one of 00000000-cfe6-495d-98cc-7fb1be768a3d, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "suggested_fix": "00000000-cfe6-495d-98cc-7fb1be768a3d",
    },
    "encrypted_token": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*encrypted[_\s-]*token).*encrypted[_\s-]*token"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*encrypted[_\s-]*token).*encrypted[_\s-]*token"),
        "allowed": {"EPQY2I6OK38NBKM", "P6TCTY312G5LF6W", "6DDCTAX11GQ6WQM", "2NDAG2G03DGDPBA", "Y35WQAQVPK9W3ZD", "UIQD2VRFUN7KOJO", "4UP34ITYZ319JCB", "GAWZZ2XKYNBY2MX", "YE73K0BOGJJL7JR", "XVLAX98A6LDNQWD", "NLZQB2TPEF7M2QS"},
        "message": "Refresh Token example must be one of EPQY2I6OK38NBKM, P6TCTY312G5LF6W, 6DDCTAX11GQ6WQM, 2NDAG2G03DGDPBA, Y35WQAQVPK9W3ZD, UIQD2VRFUN7KOJO, 4UP34ITYZ319JCB, GAWZZ2XKYNBY2MX, YE73K0BOGJJL7JR, XVLAX98A6LDNQWD, NLZQB2TPEF7M2QS",
        "suggested_fix": "EPQY2I6OK38NBKM",
    },
    "phone_number": {
        "key_re": re.compile(r"(?i)^(?!.*(?:last|first).*phone[_\s-]*number).*phone[_\s-]*number"),
        "hint_re": re.compile(r"(?i)^(?!.*(?:last|first).*phone[_\s-]*number).*phone[_\s-]*number"),
        "allowed": {"(000) 000-0000", "(555) 555-1111", "(555) 555-2222"},
        "message": "Phone Number example must be one of (000) 000-0000, (555) 555-1111 or (555) 555-2222",
        "suggested_fix": "(000) 000-0000",
    },

}

@dataclass
class Violation:
    file: str
    bad_text: str
    message: str
    suggested_fix: Optional[str] = None
    line: Optional[int] = None
    lines: list[int] = field(default_factory=list)
    fingerprint: Optional[str] = None


class TextUtils:
    @staticmethod
    def normalize_token(tok: str) -> str:
        tok = (tok or "").strip()
        tok = " ".join(tok.split())
        if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
            tok = tok[1:-1].strip()
        return tok

    @staticmethod
    def safe_review_text(s: str, maxlen: int = 220) -> str:
        if s is None:
            return ""
        s = re.sub(r"[\r\n]+", " ", s)
        s = re.sub(r"\s+", " ", s).strip()
        if len(s) > maxlen:
            s = s[: maxlen - 3].rstrip() + "..."
        return s

    @staticmethod
    def suggest_closest_month(token: str, canonical_months: list[str], cutoff: float = 0.7) -> Optional[str]:
        if not token:
            return None
        lowered = [m.lower() for m in canonical_months]
        matches = difflib.get_close_matches(token.lower(), lowered, n=1, cutoff=cutoff)
        if not matches:
            return None
        idx = lowered.index(matches[0])
        return canonical_months[idx]

    @staticmethod
    def split_sentences(text: str) -> list[str]:
        if not text:
            return []
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            return []
        if NLP is not None:
            try:
                doc = NLP(text)
                sents = [sent.text.strip() for sent in doc.sents if sent.text.strip()]
                if sents:
                    return sents
            except Exception:
                pass
        return [s.strip() for s in SENTENCE_SPLIT_RE.split(text) if s.strip()]

    @staticmethod
    def extract_context(text: str, match_start: int, match_end: int, window_words: int = 3) -> str:
        if not text:
            return ""
        words = list(re.finditer(r"\S+", text))
        if not words:
            start = max(0, match_start - 20)
            end = min(len(text), match_end + 20)
            return re.sub(r"\s+", " ", text[start:end]).strip()

        word_index = None
        for i, w in enumerate(words):
            if w.start() <= match_start < w.end():
                word_index = i
                break
        if word_index is None:
            start = max(0, match_start - 20)
            end = min(len(text), match_end + 20)
            return re.sub(r"\s+", " ", text[start:end]).strip()

        start_i = max(0, word_index - window_words)
        end_i = min(len(words), word_index + window_words + 1)
        snippet = text[words[start_i].start():words[end_i - 1].end()]
        return re.sub(r"\s+", " ", snippet).strip()


class GitHubHelpers:
    @staticmethod
    def extract_head_sha_from_review_body(body: str) -> Optional[str]:
        if not body:
            return None
        m = re.search(r"(?im)^Head SHA:\s*([0-9a-f]{7,40})\s*$", body)
        return m.group(1) if m else None

    @staticmethod
    def latest_automated_review(pull_obj):
        try:
            reviews = list(pull_obj.get_reviews())
        except Exception as e:
            print(f"Failed to read PR reviews: {e}")
            return None

        matches = []
        for review in reviews:
            body = review.body or ""
            if not body.startswith("Automated review"):
                continue
            sha = GitHubHelpers.extract_head_sha_from_review_body(body)
            if not sha:
                continue
            matches.append(
                {
                    "state": (review.state or "").upper(),
                    "sha": sha,
                    "body": body,
                    "submitted_at": getattr(review, "submitted_at", None),
                }
            )
        if not matches:
            return None
        matches.sort(key=lambda x: x["submitted_at"] or datetime.min.replace(tzinfo=timezone.utc))
        return matches[-1]


class ReviewFormatter:
    @staticmethod
    def build(violations: list[Violation], head_sha: str) -> str:
        grouped: dict[str, list[Violation]] = defaultdict(list)
        for v in violations:
            grouped[v.file].append(v)

        lines = ["Automated review conducted.", f"Head SHA: {head_sha}", ""]

        for file in sorted(grouped.keys()):
            lines.append(f"**File Name: {os.path.basename(file)}**")
            lines.append("")
            for v in grouped[file]:
                bad_text = TextUtils.safe_review_text(v.bad_text or "", 120)
                message = TextUtils.safe_review_text(v.message or "", 240)
                suggested = TextUtils.safe_review_text(str(v.suggested_fix), 120) if v.suggested_fix else None

                loc = None
                if v.lines:
                    loc = f"LINE {v.lines[0]}" if len(v.lines) == 1 else "LINES " + ", ".join(str(n) for n in v.lines)
                elif v.line:
                    loc = f"LINE {v.line}"

                def render(text: str) -> str:
                    text = TextUtils.safe_review_text(text or "", 120)
                    # If the text already contains inline code, keep it as normal text
                    # so the inline formatting is preserved.
                    return text if "`" in text else f"`{text}`"

                if suggested:
                    lines.append(
                        f"- **{loc}:** {render(bad_text)} -> {render(suggested)} - {message}"
                        if loc
                        else f"- {render(bad_text)} -> {render(suggested)} - {message}"
                    )
                else:
                    lines.append(
                        f"- **{loc}:** {render(bad_text)} - {message}"
                        if loc
                        else f"- {render(bad_text)} - {message}"
                    )
            lines.append("")

        return "\n".join(lines).rstrip()


# =============================================================================
# Scanner
# =============================================================================
class JsonPrScanner:
    def __init__(self):
        self.allowed_date_regex = re.compile(
            r"^(January|February|March|April|May|June|July|August|September|October|November|December) "
            r"(?:[1-9]|[12][0-9]|3[01]), \d{4}$",
            flags=re.UNICODE,
        )
        self.canonical_months = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        ]
        self.abbrev_lower = {a.lower() for a in ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]}
        self.canonical_lower = {m.lower() for m in self.canonical_months}
        self.seen: set[tuple] = set()

    def scan_date_checks(self, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        TARGET_DATE_KEYS = {"x-lastupdated", "lastupdated"}

        for match in MONTH_PATTERN.finditer(raw):
            month_word, day_str, year_str = match.group(1), match.group(2), match.group(3)
            token = TextUtils.normalize_token(match.group(0))

            line_no, _, _ = self.resolve_line_number(raw, token=token, key_index=key_index)
            if line_no is None:
                continue

            line_text = raw.splitlines()[line_no - 1].lower()
            if not any(k in line_text for k in TARGET_DATE_KEYS):
                continue

            reason_parts: list[str] = []

            try:
                pr_date = datetime.strptime(token, "%B %d, %Y").replace(tzinfo=timezone.utc)
            except ValueError:
                reason_parts.append("invalid calendar date")
                line_no, line_numbers, _ = self.resolve_line_number(raw, token=token, key_index=key_index)
                self.add_violation(
                    violations,
                    filename,
                    token,
                    "; ".join(reason_parts),
                    None,
                    line=line_no,
                    lines=line_numbers,
                )
                continue

            current_time = datetime.now(timezone.utc)
            time_diff = current_time - pr_date
            is_stale_date = False
            if time_diff.total_seconds() > 24 * 60 * 60:
                is_stale_date = True
                reason_parts.append(
                    f"date is older than 24 hours from current system time. Date should be `{current_time.strftime('%B')} {current_time.day}, {current_time.year}`"
                )

            suggestion = TextUtils.suggest_closest_month(month_word, self.canonical_months, cutoff=0.7)
            if not self.allowed_date_regex.fullmatch(token):
                mw_lower = month_word.lower()
                if suggestion and suggestion.lower() != mw_lower:
                    reason_parts.append(f"month looks misspelled: '{month_word}' -> '{suggestion}'")
                elif mw_lower in self.abbrev_lower:
                    reason_parts.append(f"uses abbreviation '{month_word}' (use full month name)")
                elif mw_lower not in self.canonical_lower:
                    reason_parts.append(f"invalid month name: '{month_word}'")

                if day_str.startswith("0"):
                    reason_parts.append("day has leading zero (use e.g. '1' not '01')")

            if reason_parts:
                line_no, line_numbers, _ = self.resolve_line_number(raw, token=token, key_index=key_index)
                corrected_month = current_time.strftime('%B') if is_stale_date else (suggestion or month_word)
                corrected_day = str(current_time.day) if is_stale_date else (str(int(day_str)) if day_str.startswith("0") and day_str.isdigit() else day_str)
                corrected_year = str(current_time.year) if is_stale_date else year_str
                message = "; ".join(reason_parts) + ". Expected format: Month D, YYYY (example: November 1, 2025)."
                self.add_violation(
                    violations,
                    filename,
                    token,
                    message,
                    f"{corrected_month} {corrected_day}, {corrected_year}",
                    line=line_no,
                    lines=line_numbers,
                )

    @staticmethod
    def build_new_file_lines(raw: str, is_full_content: bool) -> list[str]:
        if not raw:
            return []
        if is_full_content:
            return raw.splitlines()

        mapping: dict[int, str] = {}
        max_line = 0
        new_line_num: Optional[int] = None
        for raw_line in raw.splitlines():
            if raw_line.startswith("@@"):
                try:
                    parts = raw_line.split()
                    plus_part = next((p for p in parts if p.startswith("+")), None)
                    if plus_part:
                        plus_part = plus_part.lstrip("+")
                        start_str = plus_part.split(",")[0] if "," in plus_part else plus_part
                        new_line_num = int(start_str)
                    else:
                        new_line_num = 1
                except Exception:
                    new_line_num = None
                continue
            if new_line_num is None or raw_line.startswith("\\"):
                continue
            line_type = raw_line[:1]
            content = raw_line[1:]
            if line_type in (" ", "+"):
                mapping[new_line_num] = content
                max_line = max(max_line, new_line_num)
                new_line_num += 1
        return [mapping.get(i, "") for i in range(1, max_line + 1)] if max_line else []

    @staticmethod
    def build_key_index(raw: str) -> dict[tuple[str, ...], list[int]]:
        index: dict[tuple[str, ...], list[int]] = defaultdict(list)
        if not raw:
            return index

        i = 0
        n = len(raw)
        line_no = 1

        def advance() -> str:
            nonlocal i, line_no
            ch = raw[i]
            i += 1
            if ch == "\n":
                line_no += 1
            return ch

        def skip_ws() -> None:
            nonlocal i
            while i < n and raw[i].isspace():
                advance()

        def parse_string() -> tuple[str, int]:
            nonlocal i, line_no
            start_line = line_no
            if i >= n or raw[i] != '"':
                return "", start_line
            advance()
            buf: list[str] = []
            escaped = False
            while i < n:
                ch = raw[i]
                if escaped:
                    buf.append(ch)
                    escaped = False
                    advance()
                    continue
                if ch == "\\":
                    escaped = True
                    advance()
                    continue
                if ch == '"':
                    advance()
                    return "".join(buf), start_line
                buf.append(ch)
                advance()
            return "".join(buf), start_line

        def parse_primitive() -> None:
            nonlocal i
            while i < n:
                ch = raw[i]
                if ch in ",}]":
                    return
                advance()

        def parse_value(current_path: list[str]) -> None:
            skip_ws()
            if i >= n:
                return
            ch = raw[i]
            if ch == "{":
                parse_object(current_path)
            elif ch == "[":
                parse_array(current_path)
            elif ch == '"':
                parse_string()
            else:
                parse_primitive()

        def parse_object(current_path: list[str]) -> None:
            nonlocal i
            if i >= n or raw[i] != "{":
                return
            advance()
            skip_ws()
            if i < n and raw[i] == "}":
                advance()
                return
            while i < n:
                skip_ws()
                if i >= n:
                    return
                if raw[i] == "}":
                    advance()
                    return
                key_text, key_line = parse_string()
                skip_ws()
                if i < n and raw[i] == ":":
                    advance()
                path_tuple = tuple(current_path + [key_text])
                index[path_tuple].append(key_line)
                parse_value(current_path + [key_text])
                skip_ws()
                if i < n and raw[i] == ",":
                    advance()
                    continue
                if i < n and raw[i] == "}":
                    advance()
                    return
                return

        def parse_array(current_path: list[str]) -> None:
            nonlocal i
            if i >= n or raw[i] != "[":
                return
            advance()
            skip_ws()
            if i < n and raw[i] == "]":
                advance()
                return
            idx = 0
            while i < n:
                parse_value(current_path + [f"[{idx}]"])
                idx += 1
                skip_ws()
                if i < n and raw[i] == ",":
                    advance()
                    continue
                if i < n and raw[i] == "]":
                    advance()
                    return
                return

        skip_ws()
        if i < n:
            parse_value([])
        return index

    def add_violation(
        self,
        violations: list[Violation],
        file: str,
        bad_text: str,
        message: str,
        suggested_fix: Optional[str] = None,
        line: Optional[int] = None,
        lines: Optional[list[int]] = None,
        fingerprint: Optional[str] = None,
    ) -> None:
        key = (file, line, bad_text, message, suggested_fix, fingerprint)
        if key in self.seen:
            return
        self.seen.add(key)
        violations.append(
            Violation(
                file=file,
                bad_text=bad_text,
                message=message,
                suggested_fix=suggested_fix,
                line=line,
                lines=lines or ([line] if line is not None else []),
                fingerprint=fingerprint,
            )
        )

    @staticmethod
    def add_violation_static(
        violations: list[Violation],
        file: str,
        bad_text: str,
        message: str,
        suggested_fix: Optional[str] = None,
        line: Optional[int] = None,
        lines: Optional[list[int]] = None,
        fingerprint: Optional[str] = None,
    ) -> None:
        violations.append(
            Violation(
                file=file,
                bad_text=bad_text,
                message=message,
                suggested_fix=suggested_fix,
                line=line,
                lines=lines or ([line] if line is not None else []),
                fingerprint=fingerprint,
            )
        )

    @staticmethod
    def resolve_line_number(
        raw: str,
        *,
        token: Optional[str] = None,
        key: Optional[str] = None,
        path: Optional[list[str] | tuple[str, ...] | str] = None,
        value: Optional[str] = None,
        error: Optional[Exception] = None,
        occurrence: int = 1,
        use_regex: bool = False,
        key_index: Optional[dict[tuple[str, ...], list[int]]] = None,
    ) -> tuple[Optional[int], list[int], Optional[int]]:
        if error is not None and hasattr(error, "lineno"):
            line_no = getattr(error, "lineno", None)
            col_no = getattr(error, "colno", None)
            return line_no, ([line_no] if line_no else []), col_no

        if not raw:
            return None, [], None

        def normalize_path(path_value: Optional[list[str] | tuple[str, ...] | str]) -> list[str]:
            if path_value is None:
                return []
            if isinstance(path_value, str):
                return [part for part in path_value.split(".") if part]
            return [str(part) for part in path_value if str(part)]

        lookup_path = normalize_path(path)
        if key is not None:
            lookup_path = lookup_path + [str(key)]
            index = key_index if key_index is not None else JsonPrScanner.build_key_index(raw)
            indexed = index.get(tuple(lookup_path), [])
            if indexed:
                idx = min(max(occurrence - 1, 0), len(indexed) - 1)
                return indexed[idx], indexed, None

        lines = raw.splitlines()
        matches: list[int] = []

        if token is not None:
            pattern = None
            if use_regex:
                try:
                    pattern = re.compile(token)
                except re.error:
                    pattern = None
            for i, line in enumerate(lines, start=1):
                if pattern is not None:
                    if pattern.search(line):
                        matches.append(i)
                elif token in line:
                    matches.append(i)
        elif key is not None:
            key_text = f'"{str(key).strip()}"'.lower()
            value_norm = re.sub(r"\s+", " ", value or "").strip().lower() if value is not None else ""
            for i, line in enumerate(lines, start=1):
                line_norm = re.sub(r"\s+", " ", line).strip().lower()
                if key_text not in line_norm:
                    continue
                if value is None or value_norm in line_norm:
                    matches.append(i)

        if not matches:
            return None, [], None

        idx = min(max(occurrence - 1, 0), len(matches) - 1)
        return matches[idx], matches, None

    def validate_json_or_add_violation(self, raw: str, filename: str, violations: list[Violation]) -> bool:
        try:
            json.loads(raw)
            return True
        except json.JSONDecodeError as exc:
            line_no, _, col_no = self.resolve_line_number(raw, error=exc)
            lines = raw.splitlines()
            bad_line = lines[line_no - 1].strip() if line_no and 1 <= line_no <= len(lines) else ""
            message = f"Invalid JSON syntax: {exc.msg}."
            if line_no is not None and col_no is not None:
                message += f" Line {line_no}, column {col_no}."
            self.add_violation(violations, filename, bad_line or "Invalid JSON", message, suggested_fix=None, line=line_no)
            return False
        except Exception as exc:
            self.add_violation(violations, filename, "Invalid JSON", f"Invalid JSON syntax: {exc}.", suggested_fix=None, line=None)
            return False

    @staticmethod
    def classify_open_tag(tag_text: str, tag_name: str) -> str:
        t = tag_text.strip()
        if tag_name == "ul":
            if re.fullmatch(r"(?i)<ul\s+class\s*=\s*(['\"])pad-3-l\1\s*>", t):
                return "allowed"
            if re.fullmatch(r"(?i)<ul\s*>", t):
                return "plain"
            return "invalid_attrs"
        if tag_name == "ol":
            if re.fullmatch(r"(?i)<ol\s+class\s*=\s*(['\"])pad-3-l\1\s*>", t):
                return "allowed"
            if re.fullmatch(r"(?i)<ol\s*>", t):
                return "plain"
            return "invalid_attrs"
        return "invalid_attrs"

    def detect_malformed_tags(self, lines, raw, filename, violations):
        pattern = re.compile(r"<[A-Za-z][^>]*<[^>]*>")

        for idx, line_text in enumerate(lines, start=1):
            if not line_text:
                continue

            for match in pattern.finditer(line_text):
                bad = match.group(0)

                line_no, line_numbers, _ = self.resolve_line_number(
                    raw,
                    token=line_text.strip()
                )

                self.add_violation(
                    violations,
                    filename,
                    bad,
                    "Malformed HTML tag: missing closing '>' before another tag starts.",
                    "Ensure the tag is properly closed, e.g. <tag ...>...</tag>",
                    line=line_no,
                    lines=line_numbers
                )
    def validate_tag_family(self, lines: list[str], raw: str, filename: str, tag_name: str, violations: list[Violation]) -> None:
        open_name = f"`<{tag_name}>`"
        close_name = f"`</{tag_name}>`"
        allowed_tag = f"`<{tag_name} class='pad-3-l'>`"
        paired_fix = f"`<{tag_name} class='pad-3-l'></{tag_name}>`"

        stack = []
        line_occurrence: dict[str, int] = defaultdict(int)

        for idx, line_text in enumerate(lines, start=1):
            if not line_text:
                continue
            if BROKEN_TAG_RE.search(line_text):
                continue
            for m in re.finditer(rf"(?i)</?{tag_name}\b[^>]*>", line_text):
                tag = m.group(0)
                line_occurrence[line_text] += 1
                occurrence = line_occurrence[line_text]

                if tag.lower().startswith(f"<{tag_name}"):
                    status = self.classify_open_tag(tag, tag_name)
                    stack.append({"line_text": line_text, "occurrence": occurrence, "tag": tag, "status": status})
                    continue

                if stack:
                    opening = stack.pop()
                    status = opening["status"]
                    opening_tag = opening["tag"]
                    line_no, line_numbers, _ = self.resolve_line_number(raw, token=opening["line_text"].strip(), occurrence=opening["occurrence"])
                    if status == "plain":
                        self.add_violation(violations, filename, open_name, f"Use {allowed_tag} instead of a plain {open_name}.", allowed_tag, line=line_no, lines=line_numbers)
                    elif status == "invalid_attrs":
                        self.add_violation(violations, filename, opening_tag, f"Use {paired_fix}; other classes or ids are not allowed inside the {open_name} tag.", paired_fix, line=line_no, lines=line_numbers)
                else:
                    line_no, line_numbers, _ = self.resolve_line_number(raw, token=line_text.strip(), occurrence=occurrence)
                    self.add_violation(violations, filename, close_name, f"Orphan closing {close_name}.", paired_fix, line=line_no, lines=line_numbers)

        while stack:
            opening = stack.pop()
            status = opening["status"]
            line_no, line_numbers, _ = self.resolve_line_number(raw, token=opening["line_text"].strip(), occurrence=opening["occurrence"])
            if status == "allowed":
                self.add_violation(violations, filename, allowed_tag, f"Opening {allowed_tag} was never closed.", None, line=line_no, lines=line_numbers)
            elif status == "plain":
                self.add_violation(violations, filename, open_name, f"Orphan opening {open_name}.", paired_fix, line=line_no, lines=line_numbers)
            else:
                self.add_violation(violations, filename, opening["tag"], f"Use {paired_fix}; other classes or ids are not allowed inside the {open_name} tag.", paired_fix, line=line_no, lines=line_numbers)

    def validate_span_font_weight_medium(self, lines: list[str], raw: str, filename: str, violations: list[Violation]) -> None:
        pattern = re.compile(r"(?i)<span\b[^>]*\bclass\s*=\s*[^>]*(?<![\w-])font-weight-medium(?![\w-])[^>]*>")
        for idx, line_text in enumerate(lines, start=1):
            if not line_text:
                continue
            for m in pattern.finditer(line_text):
                self.add_violation(
                    violations,
                    filename,
                    m.group(0),
                    "Use `<b></b>` instead of `<span class='font-weight-medium'></span>`.",
                    "`<b></b>`",
                    line=idx,
                    lines=[idx],
                )

    @staticmethod
    def should_ignore_digit(segment: str, match: re.Match) -> bool:
        start, end = match.start(), match.end()
        window_start = max(0, start - 20)
        window_end = min(len(segment), end + 20)
        context = segment[window_start:window_end]
        return any(p.search(context) for p in IGNORE_DIGIT_CONTEXTS)

    def detect_hyphenation_candidates(self, sentence: str) -> tuple[list[tuple[int, int]], list[dict[str, Any]]]:
        spans: list[tuple[int, int]] = []
        issues: list[dict[str, Any]] = []
        if not sentence:
            return spans, issues

        unit_pattern = "|".join(re.escape(u) for u in sorted(HYPHENATION_UNITS, key=len, reverse=True))

        if NLP is None:
            pattern = re.compile(
                rf'\b(?P<num>\d+)\s+(?P<unit>{unit_pattern})\s+(?P<head>[A-Za-z][A-Za-z\-]*(?:\s+[A-Za-z][A-Za-z\-]*)*)',
                flags=re.IGNORECASE,
            )
            for m in pattern.finditer(sentence):
                original = m.group(0)
                if re.search(r'(?i)\b(?:is|are|was|were|be|been|being)\b.*\b\d+\s+digit\s+number\b', sentence):
                    continue
                suggested = re.sub(r'^\s*(\d+)\s+([A-Za-z]+)', r'\1-\2', original, count=1)
                if suggested == original:
                    continue
                spans.append((m.start(), m.end()))
                issues.append({
                    "bad_text": original,
                    "suggested_fix": suggested,
                    "message": 'Use a hyphen in number + noun phrases, for example "3-digit ISO code".',
                    "start": m.start(),
                    "end": m.end(),
                })
            return spans, issues

        doc = NLP(sentence)
        for i, tok in enumerate(doc[:-1]):
            if not tok.like_num:
                continue
            unit = doc[i + 1]
            if unit.lower_ not in HYPHENATION_UNITS:
                continue

            head = None
            try:
                if unit.head is not None and unit.head.i > i + 1 and unit.head.pos_ in {"NOUN", "PROPN"}:
                    head = unit.head
            except Exception:
                head = None
            if head is None:
                for j in range(i + 2, min(i + 7, len(doc))):
                    if doc[j].pos_ in {"NOUN", "PROPN"}:
                        head = doc[j]
                        break
            if head is None:
                continue
            try:
                if head.lemma_.lower() == "number" and (head.head is not None and head.head.lemma_.lower() == "be"):
                    continue
            except Exception:
                pass

            start = tok.idx
            end = head.idx + len(head)
            original = sentence[start:end]
            suggested = re.sub(rf'\b{re.escape(tok.text)}\s+{re.escape(unit.text)}\b', f"{tok.text}-{unit.text}", original, count=1)
            if suggested == original:
                continue
            spans.append((start, end))
            issues.append({
                "bad_text": original,
                "suggested_fix": suggested,
                "message": 'Use a hyphen in number + noun phrases, for example "3-digit ISO code".',
                "start": start,
                "end": end,
            })

        return spans, issues

    def iter_scannable_text_segments(self, text: str) -> Iterable[str]:
        if not text:
            return
        token_re = re.compile(r"(<[^>]+>|[^<]+)")
        stack = []

        def allowed_to_scan() -> bool:
            return not stack or all(tag == "p" for tag in stack)

        for token in token_re.findall(text):
            if not token:
                continue
            if token.startswith("<") and token.endswith(">"):
                raw = token[1:-1].strip()
                if not raw or raw.startswith("!"):
                    continue
                is_closing = raw.startswith("/")
                if is_closing:
                    tag_name = raw[1:].split(None, 1)[0] if raw[1:].strip() else ""
                    if stack:
                        for i in range(len(stack) - 1, -1, -1):
                            if stack[i] == tag_name:
                                stack.pop(i)
                                break
                    continue
                tag_name = raw.split(None, 1)[0].rstrip("/").lower()
                is_self_closing = raw.lower().endswith("/") or tag_name in HTML_VOID_TAGS
                if not is_self_closing:
                    stack.append(tag_name)
            else:
                if allowed_to_scan():
                    yield token

    def scan_description_digits(self, parsed: Any, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        def scan_sentence(sentence: str, line_no: Optional[int], field_name: str) -> None:
            if not sentence:
                return
            if re.search(r"\b(2\s*way|two\s+way)\b", sentence, re.IGNORECASE):
                return
            hyphen_spans, hyphen_issues = self.detect_hyphenation_candidates(sentence)
            for issue in hyphen_issues:
                self.add_violation(violations, filename, issue["bad_text"], issue["message"], issue["suggested_fix"], line=line_no)
            for match in SINGLE_DIGIT_RE.finditer(sentence):
                if any(start <= match.start() < end for start, end in hyphen_spans):
                    continue
                if self.should_ignore_digit(sentence, match):
                    continue

                digit = match.group(1)
                word = DIGIT_WORDS.get(digit, digit)

                # Try to include the next word so we get "4 digits" / "4 characters"
                tail = sentence[match.end():]
                next_word = re.match(r"\s+([A-Za-z][A-Za-z-]*)", tail)
                phrase_end = match.end() + next_word.end() if next_word else match.end()

                phrase = sentence[match.start():phrase_end]
                replacement = word + phrase[len(digit):]  # "four digits", "four characters"

                # Keep the comment local, not the whole sentence
                snippet = TextUtils.extract_context(sentence, match.start(), phrase_end)

                bad_text = snippet.replace(phrase, f"`{phrase}`", 1)
                suggested = snippet.replace(phrase, f"`{replacement}`", 1)

                self.add_violation(violations, filename, bad_text, 'Spell out zero through nine in "description" fields when standing alone.', suggested, line=line_no,)

        def scan_field_value(field_name: str, field_value: Any, line_no: Optional[int]) -> None:
            if not isinstance(field_value, str):
                return
            for segment in self.iter_scannable_text_segments(field_value):
                for sentence in TextUtils.split_sentences(segment):
                    scan_sentence(sentence, line_no, field_name)

        def walk(obj: Any, path: list[str]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_name = str(k).strip().lower()
                    if key_name in DESCRIPTION_KEYS_DIGITS:
                        line_no, _, _ = self.resolve_line_number(raw, path=path, key=k, value=str(v), key_index=key_index)
                        scan_field_value(key_name, v, line_no)
                    walk(v, path + [str(k)])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])

    def scan_american_express(self, parsed: Any, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        rules = [
            ("amex", AMEX_VARIANTS_RE, "Spell out American Express instead of Amex, AMEX, AmEx or AXP.", "American Express"),
            ("aed", AED_RE, "Spell out American Express Developers in description fields instead of AED.", "American Express Developers"),
        ]

        def scan_segment(segment: str, line_no: Optional[int], field_name: str):
            for rule_id, regex, message, suggested_fix in rules:
                for match in regex.finditer(segment):
                    context = TextUtils.extract_context(segment, match.start(), match.end())
                    self.add_violation(violations, filename, context, message, suggested_fix, line=line_no, fingerprint=f"{rule_id}:{match.group(0).lower()}")

        def scan_field_value(field_name: str, field_value: Any, line_no: Optional[int]) -> None:
            if not isinstance(field_value, str):
                return
            for segment in self.iter_scannable_text_segments(field_value):
                scan_segment(segment, line_no, field_name)

        def walk(obj: Any, path: list[str]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_name = str(k).strip().lower()
                    if key_name in DESCRIPTION_KEYS_TEXT:
                        line_no, _, _ = self.resolve_line_number(raw, path=path, key=k, value=str(v), key_index=key_index)
                        scan_field_value(key_name, v, line_no)
                    walk(v, path + [str(k)])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])

    def scan_capitalization(self, parsed: Any, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        all_fields = {f.lower() for r in CAPITALIZATION_RULES for f in r["fields"]}

        def scan_segment(segment: str, line_no: Optional[int], field_name: str) -> None:
            for rule in CAPITALIZATION_RULES:
                if field_name not in rule["fields"]:
                    continue
                for match in rule["regex"].finditer(segment):
                    matched_text = match.group(0)
                    expected = rule["term"]
                    if matched_text == expected:
                        continue
                    if matched_text.lower() == expected.lower():
                        matched_words = matched_text.split()
                        expected_words = expected.split()
                        if rule.get("allow_sentence_start", True) and len(expected_words) > 1 and len(matched_words) == len(expected_words) and matched_words[1:] == expected_words[1:]:
                            continue
                    context = TextUtils.extract_context(segment, match.start(), match.end())
                    self.add_violation(violations, filename, context, rule["message"], rule["suggested_fix"], line=line_no)

        def scan_field_value(field_name: str, field_value: Any, line_no: Optional[int]) -> None:
            if not isinstance(field_value, str):
                return
            for segment in self.iter_scannable_text_segments(field_value):
                scan_segment(segment, line_no, field_name)

        def walk(obj: Any, path: list[str]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_name = str(k).strip().lower()
                    if key_name in all_fields:
                        line_no, _, _ = self.resolve_line_number(raw, path=path, key=k, value=str(v), key_index=key_index)
                        scan_field_value(key_name, v, line_no)
                    walk(v, path + [str(k)])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])

    def scan_duplicate_keys(self, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        try:
            root = json.loads(raw, object_pairs_hook=list)
        except Exception:
            return

        seen_violations = set()

        def is_object_pairs(node: Any) -> bool:
            return isinstance(node, list) and all(isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) for item in node)

        def walk(node: Any, path: list[str]):
            if is_object_pairs(node):
                local_seen = defaultdict(int)
                for key, value in node:
                    local_seen[key] += 1
                    if local_seen[key] > 1:
                        current_path = ".".join(path + [key]) if path else key
                        if current_path not in seen_violations:
                            seen_violations.add(current_path)
                            line_no, line_numbers, _ = self.resolve_line_number(raw, path=path, key=key, occurrence=local_seen[key], key_index=key_index)
                            self.add_violation(
                                violations,
                                filename,
                                key,
                                f'Duplicate key "{key}" found in the same object at "{ ".".join(path) if path else "root" }".',
                                f'Keep only one "{key}" key in that object.',
                                line=line_no,
                                lines=line_numbers,
                            )
                    walk(value, path + [key])
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    walk(item, path + [f"[{idx}]"])

        walk(root, [])

    def scan_sation_spelling(self, parsed: Any, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None) -> None:
        def scan_string_value(value: str, line_no: Optional[int]) -> None:
            if not value or "isation" not in value:
                return

            for match in re.finditer(r"isation", value):
                # Expand from the matched substring to the full word
                start = match.start()
                end = match.end()

                while start > 0 and value[start - 1].isalpha():
                    start -= 1
                while end < len(value) and value[end].isalpha():
                    end += 1

                bad_word = value[start:end]
                suggested_word = bad_word.replace("sation", "zation", 1)

                snippet = TextUtils.extract_context(value, start, end)
                snippet = snippet.replace(bad_word, f"`{bad_word}`", 1)

                suggested = TextUtils.extract_context(value, start, end)
                suggested = suggested.replace(bad_word, f"`{suggested_word}`", 1)

                self.add_violation(
                    violations,
                    filename,
                    snippet,
                    "Use z spelling: replace 'sation' with 'zation'.",
                    suggested,
                    line=line_no,
                )

        def resolve_item_line(obj_value: str, path: list[str], key: Optional[str] = None) -> Optional[int]:
            line_no, _, _ = self.resolve_line_number(raw, path=path, key=key, value=obj_value, key_index=key_index)
            if line_no is None:
                line_no, _, _ = self.resolve_line_number(raw, token=obj_value, key_index=key_index)
            return line_no

        def walk(obj: Any, path: list[str]) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        line_no = resolve_item_line(v, path, key=str(k))
                        scan_string_value(v, line_no)
                    walk(v, path + [str(k)])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])
            elif isinstance(obj, str):
                line_no = resolve_item_line(obj, path)
                scan_string_value(obj, line_no)

        walk(parsed, [])


    def scan_dash_usage(self,parsed: Any,raw: str,filename: str,violations: list[Violation],key_index: Optional[dict[tuple[str, ...], list[int]]] = None,) -> None:
        def scan_string(value: str, path: list[str], key: Optional[str]):
            if not value:
                return

            # --- Case 1: space dash space ---
            for match in DASH_WITH_SPACE_RE.finditer(value):
                start, end = match.start(), match.end()

                snippet = TextUtils.extract_context(value, start, end)

                # replace only this occurrence
                fixed_value = value[:start] + " - " + value[end:]
                suggested_snippet = TextUtils.extract_context(fixed_value, start, start + 3)

                line_no, _, _ = self.resolve_line_number(
                    raw,
                    path=path,
                    key=key,
                    value=value,
                    key_index=key_index
                )

                self.add_violation(
                    violations,
                    filename,
                    snippet,
                    "Replace ' – ' or ' — ' with ' - ' (space-hyphen-space) for consistency.",
                    suggested_snippet,
                    line=line_no
                )

            # --- Case 2: no space dash ---
            for match in DASH_NO_SPACE_RE.finditer(value):
                start, end = match.start(), match.end()

                snippet = TextUtils.extract_context(value, start, end)

                fixed_value = value[:start] + "-" + value[end:]
                suggested_snippet = TextUtils.extract_context(fixed_value, start, start + 1)

                line_no, _, _ = self.resolve_line_number(
                    raw,
                    path=path,
                    key=key,
                    value=value,
                    key_index=key_index
                )

                self.add_violation(
                    violations,
                    filename,
                    snippet,
                    "Replace '–' or '—' with '-' (no spaces) to match surrounding format.",
                    suggested_snippet,
                    line=line_no
                )

        def walk(obj: Any, path: list[str]):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        scan_string(v, path, str(k))
                    walk(v, path + [str(k)])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])

    def scan_phrase_normalization(self, parsed, raw, filename, violations, key_index=None):
        def format_replacement(replacement: str, style: str) -> str:
            replacement = re.sub(r"\s+", "-", replacement.strip())

            if style == "title":
                return "-".join(part[:1].upper() + part[1:].lower() for part in replacement.split("-"))
            if style == "sentence":
                return replacement[:1].upper() + replacement[1:].lower() if replacement else replacement
            return replacement.lower()

        def apply_case(segment: str, match_start: int, match_end: int, rule: dict) -> str:
            replacement = rule["replacement"]
            tail = segment[match_end:]

            for postfix_re in rule.get("force_title_case_if_followed_by", []):
                if postfix_re.search(tail):
                    return format_replacement(replacement, "title")

            prefix = segment[:match_start].rstrip()
            if not prefix or re.search(r"[.!?]\s*$", prefix):
                return format_replacement(replacement, "sentence")

            return format_replacement(replacement, "lower")

        def inject_backticks(snippet: str, matched_text: str) -> str:
            return snippet.replace(matched_text, f"`{matched_text}`", 1)

        def scan_segment(segment: str, line_no: Optional[int]):
            for rule in PHRASE_NORMALIZATION_RULES:
                for match in rule["pattern"].finditer(segment):
                    bad = match.group(0)
                    suggested = apply_case(segment, match.start(), match.end(), rule)
                    if bad == suggested:
                        continue

                    snippet = TextUtils.extract_context(segment, match.start(), match.end())
                    snippet = inject_backticks(snippet, bad)

                    message = rule["message"].format(suggested=f"`{suggested}`")
                    self.add_violation(
                        violations,
                        filename,
                        snippet,
                        message,
                        suggested,
                        line=line_no,
                    )

        def walk(obj, path):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        line_no, _, _ = self.resolve_line_number(
                            raw, path=path, key=k, value=str(v), key_index=key_index
                        )
                        for segment in self.iter_scannable_text_segments(v):
                            scan_segment(segment, line_no)
                    walk(v, path + [str(k)])

            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])
    ##########################
    def scan_pii_data(self, parsed: Any, raw: str, filename: str, violations: list[Violation], key_index: Optional[dict[tuple[str, ...], list[int]]] = None,) -> None:
        def flag_violation(example_value: Any, parent_path: list[str], rule_name: str, key_name: str) -> None:
            rule = SENSITIVE_FIELD_RULES[rule_name]
            cleaned = str(example_value).strip()
            if cleaned in rule["allowed"]:
                return

            line_no, line_numbers, _ = self.resolve_line_number(
                raw,
                path=parent_path,
                key=key_name,
                value=str(example_value),
                key_index=key_index,
            )
            self.add_violation(
                violations,
                filename,
                cleaned,
                rule["message"],
                rule["suggested_fix"],
                line=line_no,
                lines=line_numbers,
                fingerprint=f"{rule_name}:{'.'.join(parent_path + [key_name])}",
            )

        def walk(obj: Any, path: list[str]) -> None:
            if isinstance(obj, dict):
                for key, val in obj.items():
                    key_text = str(key).strip().lower().replace(" ", "_")

                    for rule_name, rule in SENSITIVE_FIELD_RULES.items():
                        if not rule["key_re"].search(key_text):
                            continue

                        child_path = path + [str(key)]

                        if isinstance(val, dict):
                            if "example" in val:
                                flag_violation(val.get("example"), child_path, rule_name, "example")
                        elif isinstance(val, list):
                            continue
                        elif val is not None:
                            flag_violation(val, path, rule_name, str(key))

                if "example" in obj:
                    for rule_name, rule in SENSITIVE_FIELD_RULES.items():
                        matched_context = False
                        for key, val in obj.items():
                            key_text = str(key).strip().lower().replace(" ", "_")
                            if rule["key_re"].search(key_text):
                                matched_context = True
                                break
                            if isinstance(val, str) and rule["hint_re"].search(val.strip()):
                                matched_context = True
                                break
                        if matched_context:
                            flag_violation(obj.get("example"), path, rule_name, "example")

                for key, val in obj.items():
                    walk(val, path + [str(key)])

            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    walk(item, path + [f"[{idx}]"])

        walk(parsed, [])
    #############################

    def process_file(self, f, pull_obj, repo_obj, violations: list[Violation]) -> None:
        filename = f.filename
        if not filename.lower().endswith(".json"):
            return

        print(f"Checking file: {filename}")
        raw = ""
        is_full_content = False

        try:
            head_ref = pull_obj.head.ref
            head_repo_obj = pull_obj.head.repo or repo_obj
            try:
                content_file = head_repo_obj.get_contents(filename, ref=head_ref)
                raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
                is_full_content = True
                print(f"Fetched full content for {filename} from {head_repo_obj.full_name}@{head_ref}")
            except UnknownObjectException:
                print(f"Could not fetch full content for {filename} in {head_repo_obj.full_name}@{head_ref}; skipping parser-first checks.")
                return
            except GithubException as e:
                print(f"GitHub API error fetching content for {filename}: {e}; skipping parser-first checks.")
                return
            except Exception as e:
                print(f"Unexpected error when fetching {filename}: {e}; skipping parser-first checks.")
                return
        except Exception as e:
            print(f"Error preparing to fetch {filename}: {e}; skipping parser-first checks.")
            return

        if not raw:
            print(f"No content available for {filename}. Skipping.")
            return

        if not self.validate_json_or_add_violation(raw, filename, violations):
            return

        parsed = json.loads(raw)
        key_index = self.build_key_index(raw)

        self.scan_date_checks(raw, filename, violations, key_index)

        file_lines = self.build_new_file_lines(raw, is_full_content)
        if file_lines:
            self.detect_malformed_tags(file_lines, raw, filename, violations)
            self.validate_tag_family(file_lines, raw, filename, "ul", violations)
            self.validate_tag_family(file_lines, raw, filename, "ol", violations)
            self.validate_span_font_weight_medium(file_lines, raw, filename, violations)
        self.scan_pii_data(parsed, raw, filename, violations, key_index)
        self.scan_phrase_normalization(parsed, raw, filename, violations, key_index)
        self.scan_description_digits(parsed, raw, filename, violations, key_index)
        self.scan_american_express(parsed, raw, filename, violations, key_index)
        self.scan_capitalization(parsed, raw, filename, violations, key_index)
        self.scan_duplicate_keys(raw, filename, violations, key_index)
        self.scan_dash_usage(parsed, raw, filename, violations, key_index)
        self.scan_sation_spelling(parsed, raw, filename, violations, key_index)


    def run(self, pull_obj, repo_obj) -> list[Violation]:
        local_violations: list[Violation] = []
        try:
            files = list(pull_obj.get_files())
        except Exception as e:
            print(f"Failed to list files for PR #{pull_obj.number}: {e}")
            files = []
        print(f"Found {len(files)} changed file(s) in PR #{pull_obj.number}.")
        for f in files:
            self.process_file(f, pull_obj, repo_obj, local_violations)
        return local_violations


# =============================================================================
# GitHub PR bot
# =============================================================================
class ContentReviewBot:
    def __init__(self, config: BotConfig, scanner: JsonPrScanner):
        self.config = config
        self.gh = Github(base_url=config.api_url, auth=Auth.Token(config.token))
        self.repo = self.gh.get_repo(config.repository)
        self.scanner = scanner

    def get_pull(self, pr_num):
        try:
            return self.repo.get_pull(pr_num)
        except Exception as e:
            print(f"Failed to fetch PR #{pr_num} from repo {self.config.repository}: {e}")
            return None

    @staticmethod
    def is_draft_pull(pull_obj) -> bool:
        return bool(getattr(pull_obj, "draft", False))

    def ensure_label(self, label_name: str, color: str = "F2F735", description: str = "") -> str:
        try:
            for lab in self.repo.get_labels():
                if lab.name.lower() == label_name.lower():
                    return lab.name
            self.repo.create_label(name=label_name, color=color, description=description)
        except Exception as e:
            print(f"Failed to ensure label '{label_name}': {e}")
        return label_name

    def apply_label(self, pr_num: int, label_name: str) -> None:
        try:
            self.repo.get_issue(pr_num).add_to_labels(label_name)
        except Exception as e:
            print(f"Failed to apply label '{label_name}' to PR #{pr_num}: {e}")

    def remove_labels(self, pr_num: int, label_names: list[str]) -> None:
        try:
            issue = self.repo.get_issue(pr_num)
            current_labels = list(issue.get_labels())
            target = {name.lower() for name in label_names}
            to_remove = [lab.name for lab in current_labels if lab.name.lower() in target]
            if to_remove:
                issue.remove_from_labels(*to_remove)
                print(f"Removed labels from PR #{pr_num}: {to_remove}")
        except Exception as e:
            print(f"Failed to remove labels {label_names} from PR #{pr_num}: {e}")

    def create_review(self, pull_obj, body: str, event: str) -> None:
        try:
            pull_obj.create_review(body=body, event=event)
            print(f"Review created ({event}).")
        except Exception as e:
            print(f"Failed to create {event} review: {e}")

    def assign_author(self, pr_num: int, author_login: Optional[str]) -> None:
        if not author_login:
            return
        try:
            self.repo.get_issue(pr_num).add_to_assignees(author_login)
        except Exception as e:
            print(f"Failed to assign PR to @{author_login}: {e}")

    def set_labels_for_state(self, pr_num: int, review_state: str) -> None:
        self.ensure_label(self.config.approved_label, color="6BFBFB", description="Bot review completed")
        self.ensure_label(self.config.correction_label, color="F2F735", description="PR needs correction")

        if review_state == "APPROVED":
            self.apply_label(pr_num, self.config.approved_label)
            self.remove_labels(pr_num, [self.config.correction_label, self.config.pending_label])
        elif review_state == "CHANGES_REQUESTED":
            self.apply_label(pr_num, self.config.correction_label)
            self.remove_labels(pr_num, [self.config.approved_label, self.config.pending_label])

    def mark_pending(self, pr_num: int) -> None:
        self.ensure_label(self.config.pending_label, color="1D76DB", description="Pending quiet-period bot review")
        self.apply_label(pr_num, self.config.pending_label)
        self.remove_labels(pr_num, [self.config.approved_label, self.config.correction_label])

    def create_or_update_review(self, pull_obj, pr_num: int, pr_author_login: Optional[str] = None) -> None:
        if self.is_draft_pull(pull_obj):
            print(f"PR #{pr_num} is a draft; skipping automated review.")
            return

        current_sha = getattr(pull_obj.head, "sha", None)
        if not current_sha:
            print(f"PR #{pr_num} has no head SHA. Skipping.")
            return

        latest = GitHubHelpers.latest_automated_review(pull_obj)
        if latest and latest.get("state") == "APPROVED":
            print(f"PR #{pr_num} already approved by bot; skipping all future reviews.")
            return
        if latest and latest.get("sha") == current_sha:
            print(f"PR #{pr_num} already has an automated review for head SHA {current_sha}; skipping duplicate review.")
            self.set_labels_for_state(pr_num, latest.get("state", ""))
            return

        violations = self.scanner.run(pull_obj, self.repo)

        if violations:
            body = ReviewFormatter.build(violations, current_sha)
            print("Review body preview:")
            print(body[:4000])
            self.create_review(pull_obj, body, "REQUEST_CHANGES")
            self.ensure_label(self.config.correction_label, color="F2F735", description="PR needs correction")
            self.apply_label(pr_num, self.config.correction_label)
            self.remove_labels(pr_num, [self.config.approved_label, self.config.pending_label])
            self.assign_author(pr_num, pr_author_login)
            return

        body = f"Automated review: Passed\nHead SHA: {current_sha}"
        self.create_review(pull_obj, body, "APPROVE")
        self.ensure_label(self.config.approved_label, color="6BFBFB", description="Bot review completed")
        self.ensure_label(self.config.manual_review_label, color="6BFBFB", description="For 1st manual review")
        self.apply_label(pr_num, self.config.approved_label)
        self.apply_label(pr_num, self.config.manual_review_label)
        self.remove_labels(pr_num, [self.config.correction_label, self.config.pending_label])

    def wait_then_review(self, pr_num: int, initial_sha: str, pr_author_login: Optional[str] = None) -> None:
        if self.config.quiet_period_minutes > 0:
            print(f"Waiting {self.config.quiet_period_minutes} minute(s) before re-reviewing PR #{pr_num}...")
            time.sleep(self.config.quiet_period_minutes * 60)

        refreshed = self.get_pull(pr_num)
        if not refreshed:
            print(f"PR #{pr_num}: could not refetch PR after wait; leaving pending.")
            return
        if getattr(refreshed, "state", "").lower() != "open":
            print(f"PR #{pr_num} is no longer open; skipping review.")
            return
        if self.is_draft_pull(refreshed):
            print(f"PR #{pr_num} is still a draft after wait; skipping review.")
            return

        current_sha = getattr(refreshed.head, "sha", None)
        print(f"PR #{pr_num}: head SHA after wait is {current_sha}, original SHA was {initial_sha}")
        if initial_sha and current_sha != initial_sha:
            print(f"PR #{pr_num}: head SHA changed while waiting; keeping pending state for the newer commit.")
            return

        self.create_or_update_review(refreshed, pr_num, pr_author_login=pr_author_login)


# =============================================================================
# Event handling
# =============================================================================
class EventProcessor:
    VALID_ACTIONS = {"opened", "reopened", "ready_for_review", "synchronize"}

    def __init__(self, config: BotConfig):
        self.config = config

    def load_event(self) -> dict[str, Any]:
        try:
            with open(self.config.event_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load event payload from {self.config.event_path}: {e}")
            sys.exit(1)

    def parse_pull_request_event(self, event: dict[str, Any]) -> tuple[Optional[int], Optional[str], Optional[str]]:
        if self.config.event_name != "pull_request":
            print("This script only supports pull_request events. Exiting.")
            sys.exit(0)

        pr_dict = event.get("pull_request") or {}
        pr_number = pr_dict.get("number")
        pr_author = pr_dict.get("user", {}).get("login")
        trigger_mode = (event.get("action") or "").lower()

        print("PR number:", pr_number)
        print("PR Author:", pr_author)
        print("PR action:", trigger_mode)

        if trigger_mode not in self.VALID_ACTIONS:
            print(f"Ignoring pull_request action '{trigger_mode}'.")
            sys.exit(0)

        if not pr_number:
            print("PR number not found in payload. Exiting.")
            sys.exit(1)

        return int(pr_number), pr_author, trigger_mode


# =============================================================================
# Main
# =============================================================================
def main() -> int:
    config = BotConfig.from_env()
    print(f"GITHUB_EVENT_PATH: {config.event_path}")
    print(f"GITHUB_REPOSITORY: {config.repository}")
    print(f"GITHUB_TOKEN length: {len(config.token)}")
    print(f"GITHUB_EVENT_NAME: {config.event_name}")
    print(f"GITHUB_ACTOR: {config.actor}")

    event_processor = EventProcessor(config)
    event = event_processor.load_event()

    pr = event.get("pull_request") or {}
    labels = [l.get("name", "").lower() for l in pr.get("labels", [])]
    if "skip-review" in labels:
        print("skip-review label found; exiting without review.")
        return 0

    pr_number, pr_author, trigger_mode = event_processor.parse_pull_request_event(event)

    scanner = JsonPrScanner()
    bot = ContentReviewBot(config, scanner)

    pull = bot.get_pull(pr_number)
    if not pull:
        return 1

    if not pr_author and getattr(pull, "user", None):
        pr_author = pull.user.login

    print(f"Processing PR #{pr_number} by @{pr_author} in repo {config.repository}")

    try:
        files = list(pull.get_files())
        has_json = any(f.filename.lower().endswith(".json") for f in files)

        if has_json:
            bot.ensure_label(
                bot.config.content_label,
                color="F910A0",
                description="PR raised by an API product team",
            )
            bot.apply_label(pr_number, bot.config.content_label)

    except Exception as e:
        print(f"Failed to check JSON files for PR #{pr_number}: {e}")

    if trigger_mode == "synchronize":
        if bot.is_draft_pull(pull):
            print(f"PR #{pr_number} is a draft; skipping pending mark and delayed review.")
            return 0
        latest = GitHubHelpers.latest_automated_review(pull)
        if latest and latest.get("state") == "APPROVED":
            print(f"PR #{pr_number} already approved by bot; skipping all future reviews.")
            return 0
        print(f"PR #{pr_number} changed; marking as pending.")
        bot.mark_pending(pr_number)
        initial_sha = getattr(pull.head, "sha", None)
        if not initial_sha:
            print(f"PR #{pr_number}: no head SHA available; skipping delayed review.")
            return 0
        bot.wait_then_review(pr_num=pr_number, initial_sha=initial_sha, pr_author_login=pr_author)
        return 0

    if trigger_mode in {"opened", "reopened", "ready_for_review"}:
        bot.create_or_update_review(pull, pr_number, pr_author_login=pr_author)
        return 0

    print(f"Unhandled trigger mode '{trigger_mode}'. Exiting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
