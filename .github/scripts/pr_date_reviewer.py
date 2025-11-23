#!/usr/bin/env python3
"""
PR date format reviewer (value-only JSON scanning) — minimal, robust, and keeps your original flow.

Behavior:
- Parses changed .json files in the PR (prefers full file content; falls back to patch).
- Parses JSON values and validates only string values for date tokens.
- Normalizes tokens (NFKC, spaces, punctuation, zero-width chars).
- Validates against allowed regex from .github/pr-rules/date_format.yml (fullmatch).
- Reports violations in a single REQUEST_CHANGES review with bullets that include LINE NO.
- Applies/creates "Correction Needed" label and assigns the PR author.
"""
import os
import json
import re
import sys
import unicodedata
from base64 import b64decode

from github import Github
from github.GithubException import UnknownObjectException
import yaml

# --- config / env ---
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables.")
    sys.exit(1)

# Load event payload
with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

# Only handle pull_request events
pr = event.get("pull_request")
if not pr:
    print("No pull_request payload found. Exiting.")
    sys.exit(0)

pr_number = pr.get("number")
pr_author = pr.get("user", {}).get("login")
if not pr_number:
    print("PR number not found; exiting.")
    sys.exit(1)

# Load rule file
RULE_PATH = ".github/pr-rules/date_format.yml"
try:
    with open(RULE_PATH, "r") as rf:
        rules = yaml.safe_load(rf) or {}
except FileNotFoundError:
    print(f"Rule file {RULE_PATH} not found — using defaults.")
    rules = {}

allowed_regex_str = rules.get("allowed_date_regex") or \
    r'^(January|February|March|April|May|June|July|August|September|October|November|December) ([1-9]|[12][0-9]|3[01]), \d{4}$'
allowed_regex = re.compile(allowed_regex_str)

# initialize GitHub client
gh = Github(GITHUB_TOKEN)
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)

files = list(pull.get_files())
violations = []

# Candidate token inside a string value: permissive capture Word D, YYYY
date_candidate_pattern = re.compile(r'\b([A-Za-z]+)\s+([0-9]{1,2}),\s+([0-9]{4})\b')

# --- helpers ---
def find_line_number_in_full_content(content: str, target: str):
    """Return 1-based line number of first line containing target (exact substring), or None."""
    idx = content.find(target)
    if idx == -1:
        return None
    return content[:idx].count('\n') + 1

def find_line_number_in_patch(patch: str, token: str):
    """
    Parse unified diff patch and return the 1-based new-file line number where token first appears.
    This tries to map token to the new file line numbers using hunk headers.
    """
    if not patch:
        return None
    new_line_num = None
    for raw_line in patch.splitlines():
        if raw_line.startswith('@@'):
            try:
                parts = raw_line.split()
                plus_part = next((p for p in parts if p.startswith('+')), None)
                if plus_part:
                    plus_part = plus_part.lstrip('+')
                    if ',' in plus_part:
                        start_str = plus_part.split(',')[0]
                    else:
                        start_str = plus_part
                    new_line_num = int(start_str)
                else:
                    new_line_num = 1
            except Exception:
                new_line_num = None
            continue

        if new_line_num is None:
            continue

        if raw_line.startswith('\\'):
            continue

        line_type = raw_line[:1]
        content = raw_line[1:]

        if token in content and line_type != '-':
            return new_line_num

        if line_type in (' ', '+'):
            new_line_num += 1

    return None

def normalize_token_for_matching(token: str) -> str:
    """
    Normalize token for regex matching:
    - Unicode NFKC (converts fullwidth digits/punct to ASCII)
    - Replace a set of special spaces with ASCII space
    - Normalize some punctuation (fullwidth comma etc.)
    - Remove common zero-width / bidi characters
    - Collapse whitespace
    """
    t = unicodedata.normalize("NFKC", token)
    # normalize common spaces
    for s in ('\u00A0', '\u202F', '\u2009', '\u2002', '\u2003', '\u3000'):
        t = t.replace(s, ' ')
    # punctuation normalization
    t = t.replace('\uFF0C', ',')  # fullwidth comma
    # remove zero-width / directionality
    t = re.sub(r'[\u200B\u200C\u200D\u200E\u200F\u2060\uFEFF]', '', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

def iter_strings_from_json(obj):
    """Yield all string values from parsed JSON (recursive)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings_from_json(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_strings_from_json(item)
    # other JSON types ignored

# --- main processing per-file ---
for f in files:
    filename = f.filename
    if not filename.lower().endswith(".json"):
        continue

    print(f"Checking file: {filename}")

    raw = ""
    is_full_content = False
    try:
        head_repo_obj = pull.head.repo or repo
        head_ref = pull.head.ref
    except Exception as e:
        print(f"Failed to read pull.head info: {e}")
        head_repo_obj = repo
        head_ref = None

    if head_ref:
        try:
            content_file = head_repo_obj.get_contents(filename, ref=head_ref)
            raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
            is_full_content = True
            print(f"Fetched content for {filename} from {head_repo_obj.full_name}@{head_ref}")
        except UnknownObjectException:
            print(f"File {filename} not found at {head_repo_obj.full_name}@{head_ref}. Using patch fallback.")
            raw = f.patch or ""
            is_full_content = False
        except Exception as e:
            print(f"Error fetching {filename}: {e}. Using patch fallback.")
            raw = f.patch or ""
            is_full_content = False
    else:
        raw = f.patch or ""
        is_full_content = False
        print(f"No head_ref; using patch fallback for {filename}.")

    if not raw:
        print(f"No content available for {filename} (empty raw). Skipping.")
        continue

    # Try parsing JSON to inspect values only (safer). Fall back to raw scanning if parse fails.
    parsed = None
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None

    if parsed is not None:
        # inspect only string values from JSON
        for val in iter_strings_from_json(parsed):
            for match in date_candidate_pattern.finditer(val):
                token_orig = match.group(0).strip()
                token_norm = normalize_token_for_matching(token_orig)
                is_allowed = bool(allowed_regex.fullmatch(token_norm))
                if not is_allowed:
                    # find line number in raw content: search for the JSON value occurrence; fallback to token search
                    line_no = None
                    try:
                        # search for exact JSON value occurrence first (with quotes)
                        idx = raw.find(f'"{val}"')
                        if idx == -1:
                            # search raw for value without quotes
                            idx = raw.find(val)
                        if idx != -1:
                            line_no = raw[:idx].count('\n') + 1
                        else:
                            # fallback: try token search
                            if is_full_content:
                                line_no = find_line_number_in_full_content(raw, token_orig) or find_line_number_in_full_content(raw, token_norm)
                            else:
                                line_no = find_line_number_in_patch(f.patch or "", token_orig) or find_line_number_in_patch(f.patch or "", token_norm)
                    except Exception:
                        line_no = None

                    violations.append({"file": filename, "bad_date": token_orig, "line": line_no})
                    if line_no:
                        print(f"Violation in {filename}: {token_orig} (line {line_no})")
                    else:
                        print(f"Violation in {filename}: {token_orig} (line unknown)")

    else:
        # fallback: scan raw text for candidates (previous behavior)
        for match in date_candidate_pattern.finditer(raw):
            token_orig = match.group(0).strip()
            token_norm = normalize_token_for_matching(token_orig)
            is_allowed = bool(allowed_regex.fullmatch(token_norm))
            if not is_allowed:
                line_no = None
                try:
                    if is_full_content:
                        line_no = find_line_number_in_full_content(raw, token_orig) or find_line_number_in_full_content(raw, token_norm)
                    else:
                        line_no = find_line_number_in_patch(f.patch or "", token_orig) or find_line_number_in_patch(f.patch or "", token_norm)
                except Exception:
                    line_no = None

                violations.append({"file": filename, "bad_date": token_orig, "line": line_no})
                if line_no:
                    print(f"Violation in {filename}: {token_orig} (line {line_no})")
                else:
                    print(f"Violation in {filename}: {token_orig} (line unknown)")

# If violations exist -> create a review REQUEST_CHANGES + add label + assign PR author
if violations:
    lines = []
    lines.append("Automated review: Date format violations detected.")
    lines.append("")
    for v in violations:
        if v.get("line"):
            lines.append(f"- LINE NO {v['line']}: File `{v['file']}` contains date `{v['bad_date']}` which is not in allowed format.")
        else:
            lines.append(f"- File `{v['file']}` contains date `{v['bad_date']}` which is not in allowed format.")
    lines.append("")
    lines.append("Expected format: `Month D, YYYY` (e.g. `November 1, 2025`). Please fix all occurrences.")
    body = "\n".join(lines)

    print("Creating review (REQUEST_CHANGES)...")
    try:
        pull.create_review(body=body, event="REQUEST_CHANGES")
        print("Review created with REQUEST_CHANGES.")
    except Exception as e:
        print(f"Failed to create review: {e}")

    LABEL_NAME = "Correction Needed"
    LABEL_COLOR = "d93f0b"
    issue = repo.get_issue(pr_number)
    try:
        found = False
        for lab in repo.get_labels():
            if lab.name.lower() == LABEL_NAME.lower():
                found = True
                break
        if not found:
            print(f"Creating label '{LABEL_NAME}'")
            repo.create_label(name=LABEL_NAME, color=LABEL_COLOR, description="PR needs correction")
        issue.add_to_labels(LABEL_NAME)
        print(f"Label '{LABEL_NAME}' applied to PR #{pr_number}")
    except Exception as e:
        print(f"Failed to add/create label: {e}")

    try:
        issue.add_to_assignees(pr_author)
        print(f"Assigned PR to {pr_author}")
    except Exception as e:
        print(f"Failed to assign PR author: {e}")

    sys.exit(0)
else:
    print("No date format violations found.")
    sys.exit(0)
