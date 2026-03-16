#!/usr/bin/env python3

import os
import sys
import json
import re
import yaml
from base64 import b64decode
from datetime import datetime

from github import Github, GithubException, Auth
from github.GithubException import UnknownObjectException


# ---------------- ENV ----------------

GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables")
    sys.exit(1)


# ---------------- LOAD EVENT ----------------

with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

pr_dict = event.get("pull_request")
if not pr_dict:
    sys.exit(0)

pr_number = pr_dict.get("number")
pr_author = pr_dict.get("user", {}).get("login")


# ---------------- DATE RULE ----------------

default_allowed_regex = r'^(January|February|March|April|May|June|July|August|September|October|November|December) (?:[1-9]|[12][0-9]|3[01]), \d{4}$'
allowed_regex = re.compile(default_allowed_regex)

date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r'|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b',
    flags=re.IGNORECASE
)

# today date
today = datetime.utcnow()
today_string = today.strftime("%B %-d, %Y") if sys.platform != "win32" else today.strftime("%B %#d, %Y")


# ---------------- GITHUB CLIENT ----------------

gh = Github(auth=Auth.Token(GITHUB_TOKEN))
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)


# ---------------- HELPERS ----------------

def normalize_token(tok):
    tok = tok.strip()
    tok = " ".join(tok.split())
    if tok.startswith('"') and tok.endswith('"'):
        tok = tok[1:-1]
    return tok


def get_section_name(filename):
    """
    nextgen-abc-xyz-overview.json -> OVERVIEW
    """
    base = os.path.basename(filename)
    name = base.split(".")[0]
    section = name.split("-")[-1]
    return section.upper()


# ---------------- PROCESS FILES ----------------

files = list(pull.get_files())
violations = {}

for f in files:

    filename = f.filename

    if not filename.endswith(".json"):
        continue

    raw = ""

    try:
        head_ref = pull.head.ref
        head_repo = pull.head.repo or repo
        content_file = head_repo.get_contents(filename, ref=head_ref)
        raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
    except Exception:
        raw = f.patch or ""

    if not raw:
        continue

    section = get_section_name(filename)

    if section not in violations:
        violations[section] = []

    lines = raw.splitlines()

    for i, line in enumerate(lines, start=1):

        # -------- DATE FORMAT CHECK --------

        for match in date_candidate_pattern.finditer(line):

            token = normalize_token(match.group(0))

            if not allowed_regex.fullmatch(token):
                violations[section].append(
                    f"LINE {i} : contains {token} which is not in format Month D, YYYY"
                )

        # -------- lastUpdate / x-modified CHECK --------

        key_match = re.search(r'"(lastUpdate|x-modified)"\s*:\s*"([^"]+)"', line)

        if key_match:

            key = key_match.group(1)
            value = key_match.group(2)

            value = normalize_token(value)

            if value != today_string:

                violations[section].append(
                    f"LINE {i} : {key} has value {value} but must be today's date {today_string}"
                )


# ---------------- CREATE REVIEW ----------------

if violations:

    body_lines = []
    body_lines.append("Automated review: Date validation errors detected.\n")

    for section, errors in violations.items():

        if not errors:
            continue

        body_lines.append(f"{section}:")

        for e in errors:
            body_lines.append(e)

        body_lines.append("")

    body = "\n".join(body_lines)

    try:
        pull.create_review(
            body=body,
            event="REQUEST_CHANGES"
        )
    except Exception as e:
        print(f"Failed creating review {e}")

    # ---- label ----

    LABEL = "Correction Needed"

    try:
        repo.create_label(
            name=LABEL,
            color="d93f0b",
            description="PR needs correction"
        )
    except:
        pass

    try:
        issue = repo.get_issue(pr_number)
        issue.add_to_labels(LABEL)
    except:
        pass

    # ---- assign ----

    try:
        issue = repo.get_issue(pr_number)
        issue.add_to_assignees(pr_author)
    except:
        pass

    sys.exit(0)

else:

    print("No violations detected")
    sys.exit(0)
