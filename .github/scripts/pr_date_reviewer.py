#!/usr/bin/env python3
import os
import json
import re
import sys
from github import Github
import yaml
from base64 import b64decode
from github.GithubException import UnknownObjectException

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
        rules = yaml.safe_load(rf)
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

date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b'
)

for f in files:
    filename = f.filename
    if not filename.lower().endswith(".json"):
        continue

    print(f"Checking file: {filename}")

    # Fix indentation of THIS whole block ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓

    try:
        # Prefer to fetch from PR head repo
        head_repo_obj = pull.head.repo or repo
        head_ref = pull.head.ref

        try:
            content_file = head_repo_obj.get_contents(filename, ref=head_ref)
            raw = b64decode(content_file.content).decode("utf-8", errors="ignore")

        except UnknownObjectException:
            print(f"Could not fetch raw content for {filename}; trying patch.")
            raw = f.patch or ""

        except Exception as e:
            print(f"Failed to get_contents for {filename}: {e}")
            raw = f.patch or ""

    except Exception as e:
        print(f"Unexpected error fetching content for {filename}: {e}")
        raw = ""

    # ↑↑↑ FIXED ONLY THIS — no logic changed

    if not raw:
        print(f"No content available for {filename} (empty raw). Skipping.")
        continue

    for match in date_candidate_pattern.finditer(raw):
        token = match.group(0).strip()
        if not allowed_regex.match(token):
            violations.append({"file": filename, "bad_date": token})
            print(f"Violation in {filename}: {token}")

# Review + Label + Assign logic (unchanged)
if violations:
    lines = ["Automated review: Date format violations detected.", ""]
    for v in violations:
        lines.append(f"- File `{v['file']}` contains date `{v['bad_date']}` which is not in allowed format.")
    lines.append("")
    lines.append("Expected format: `Month D, YYYY` (e.g. `November 1, 2025`). Please fix all occurrences.")
    body = "\n".join(lines)

    print("Creating review (REQUEST_CHANGES)...")
    try:
        pull.create_review(body=body, event="REQUEST_CHANGES")
        print("Review created.")
    except Exception as e:
        print(f"Failed to create review: {e}")

    LABEL_NAME = "Correction Needed"
    issue = repo.get_issue(pr_number)

    try:
        existing = any(lab.name.lower() == LABEL_NAME.lower() for lab in repo.get_labels())
        if not existing:
            repo.create_label(name=LABEL_NAME, color="d93f0b", description="PR needs correction")
        issue.add_to_labels(LABEL_NAME)
        print(f"Label applied to PR #{pr_number}")
    except Exception as e:
        print(f"Failed to add label: {e}")

    try:
        issue.add_to_assignees(pr_author)
        print(f"Assigned PR to {pr_author}")
    except Exception as e:
        print(f"Failed to assign PR author: {e}")

    sys.exit(0)

else:
    print("No date format violations found.")
    sys.exit(0)
