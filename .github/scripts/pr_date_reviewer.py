#!/usr/bin/env python3
"""
Robust PR date format reviewer (extended).

Checks:
1. Date format validation (Month D, YYYY).
2. Ensures JSON keys `lastUpdate` or `x-modified` contain today's system date.
3. Works with nested JSON structures.
4. Works for PRs and additional commits pushed to PR.
"""

import os
import sys
import json
import re
import yaml
from datetime import datetime
from base64 import b64decode

from github import Github, GithubException, Auth
from github.GithubException import UnknownObjectException


# ---------------- ENV ----------------

GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables")
    sys.exit(1)


# ---------------- EVENT ----------------

with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

pr_dict = event.get("pull_request")

if not pr_dict:
    print("No PR found in event payload")
    sys.exit(0)

pr_number = pr_dict["number"]
pr_author = pr_dict["user"]["login"]


# ---------------- RULES ----------------

RULE_PATH = ".github/pr-rules/date_format.yml"

default_allowed_regex = r'^(January|February|March|April|May|June|July|August|September|October|November|December) (?:[1-9]|[12][0-9]|3[01]), \d{4}$'

try:
    with open(RULE_PATH) as rf:
        rules = yaml.safe_load(rf) or {}
except:
    rules = {}

allowed_regex_str = rules.get("allowed_date_regex", default_allowed_regex)

allowed_regex = re.compile(allowed_regex_str)


# ---------------- DATE TOKEN SEARCH ----------------

date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r'|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b',
    flags=re.IGNORECASE
)


# ---------------- SYSTEM DATE ----------------

today = datetime.now()

today_string = today.strftime("%B %-d, %Y") if os.name != "nt" else today.strftime("%B %#d, %Y")

print("System Date:", today_string)


# ---------------- GITHUB ----------------

gh = Github(auth=Auth.Token(GITHUB_TOKEN))
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)

files = list(pull.get_files())

print("Files changed:", len(files))


violations = []
date_update_violations = []


# ---------------- UTILITIES ----------------

def normalize_token(tok: str) -> str:
    tok = tok.strip()
    tok = " ".join(tok.split())
    if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
        tok = tok[1:-1]
    return tok


def find_update_keys(obj, path="root"):
    """
    Recursively find lastUpdate / x-modified keys in nested JSON
    """

    results = []

    if isinstance(obj, dict):
        for k, v in obj.items():

            key_lower = k.lower()

            if key_lower in ["lastupdate", "x-modified", "x-modified-date"]:
                results.append((path + "." + k, v))

            results.extend(find_update_keys(v, path + "." + k))

    elif isinstance(obj, list):

        for i, item in enumerate(obj):
            results.extend(find_update_keys(item, path + f"[{i}]"))

    return results


# ---------------- PROCESS FILES ----------------

for f in files:

    filename = f.filename

    if not filename.lower().endswith(".json"):
        continue

    print("Checking:", filename)

    raw = ""

    try:

        head_ref = pull.head.ref
        head_repo = pull.head.repo or repo

        content = head_repo.get_contents(filename, ref=head_ref)

        raw = b64decode(content.content).decode("utf-8", errors="ignore")

    except:

        raw = f.patch or ""

    if not raw:
        continue


    # -------- DATE FORMAT CHECK --------

    for match in date_candidate_pattern.finditer(raw):

        token = normalize_token(match.group(0))

        if not allowed_regex.fullmatch(token):

            violations.append({
                "file": filename,
                "bad_date": token
            })


    # -------- JSON CHECK --------

    try:

        data = json.loads(raw)

    except:

        print("Invalid JSON:", filename)

        continue


    update_keys = find_update_keys(data)

    for path, value in update_keys:

        if isinstance(value, str):

            val_norm = normalize_token(value)

            if val_norm != today_string:

                date_update_violations.append({
                    "file": filename,
                    "key": path,
                    "value": val_norm,
                    "expected": today_string
                })


# ---------------- REVIEW ----------------

if violations or date_update_violations:

    lines = []

    lines.append("Automated review issues detected.")
    lines.append("")

    if violations:

        lines.append("### Invalid Date Format")

        for v in violations:

            lines.append(
                f"- `{v['file']}` contains `{v['bad_date']}` which is not in format `Month D, YYYY`"
            )

        lines.append("")


    if date_update_violations:

        lines.append("### Update Date Required")

        for v in date_update_violations:

            lines.append(
                f"- `{v['file']}` key `{v['key']}` has value `{v['value']}` but must be today's date `{v['expected']}`"
            )

        lines.append("")
        lines.append("Please update the value to today's system date.")


    body = "\n".join(lines)

    print("Creating review...")

    pull.create_review(
        body=body,
        event="REQUEST_CHANGES"
    )


    LABEL_NAME = "Correction Needed"

    try:

        repo.create_label(
            name=LABEL_NAME,
            color="d93f0b",
            description="PR needs correction"
        )

    except:
        pass


    issue = repo.get_issue(pr_number)

    issue.add_to_labels(LABEL_NAME)

    if pr_author:
        issue.add_to_assignees(pr_author)

    sys.exit(0)


print("No violations found")

sys.exit(0)
