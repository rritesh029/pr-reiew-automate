#!/usr/bin/env python3
import os
import json
import re
import sys
from github import Github
import yaml
from base64 import b64decode

# --- config / env ---
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")  # "owner/repo"

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables.")
    sys.exit(1)

# Load event payload (GitHub writes this for the action runner)
with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

# Only handle pull_request events
pr = event.get("pull_request")
if not pr:
    print("No pull_request payload found. Exiting.")
    sys.exit(0)

pr_number = pr.get("number")
pr_head_ref = pr.get("head", {}).get("ref")
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

# iterate changed files
files = list(pull.get_files())
violations = []  # list of dicts {file,path, example_bad_date}

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
    # Fetch file content at PR head ref
    try:
    # Prefer to fetch from the PR head repository (handles forks)
    # 'pull' is the PyGithub PullRequest object created earlier.
    head_repo_obj = pull.head.repo or repo  # pull.head.repo may be None in some edge-cases
    head_ref = pull.head.ref  # branch name in head repo (e.g. "feature/branch")

    try:
        content_file = head_repo_obj.get_contents(filename, ref=head_ref)
        raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
    except UnknownObjectException:
        # If the file isn't present at the head ref (rare) try reading the patch from the PR file entry
        # f is the file object from pull.get_files()
        print(f"Could not fetch raw content for {filename} by get_contents; trying patch.")
        raw = f.patch or ""
    except Exception as e:
        print(f"Failed to get_contents for {filename} from head repo {head_repo_obj.full_name}@{head_ref}: {e}")
        # as fallback, try to use the file.patch, then skip if not available
        raw = f.patch or ""
except Exception as e:
    print(f"Unexpected error fetching content for {filename}: {e}")
    raw = ""

    # Find candidate date tokens and validate each token with allowed regex.
    # If token exists but doesn't match allowed_regex exactly, it's a violation.
    for match in date_candidate_pattern.finditer(raw):
        token = match.group(0).strip()
        # check strict match: whole token must match allowed regex
        if not allowed_regex.match(token):
            # record violation: include first occurrence location
            # to keep simple we won't compute diff position; we'll reference filename.
            violations.append({"file": filename, "bad_date": token})
            print(f"Violation in {filename}: {token}")

# If violations exist -> create a review REQUEST_CHANGES + add label + assign PR author
if violations:
    # create a human readable message
    lines = []
    lines.append("Automated review: Date format violations detected.")
    lines.append("")
    for v in violations:
        lines.append(f"- File `{v['file']}` contains date `{v['bad_date']}` which is not in allowed format.")
    lines.append("")
    lines.append("Expected format: `Month D, YYYY` (e.g. `November 1, 2025`). Please fix all occurrences.")
    body = "\n".join(lines)

    print("Creating review (REQUEST_CHANGES)...")
    # Create review on the PR (summary-level review)
    try:
        pull.create_review(body=body, event="REQUEST_CHANGES")
        print("Review created with REQUEST_CHANGES.")
    except Exception as e:
        print(f"Failed to create review: {e}")

    # Add label "Correction Needed" (create it first if missing)
    LABEL_NAME = "Correction Needed"
    LABEL_COLOR = "d93f0b"  # orange-red
    issue = repo.get_issue(pr_number)
    try:
        # check labels in repo
        found = False
        for lab in repo.get_labels():
            if lab.name.lower() == LABEL_NAME.lower():
                found = True
                break
        if not found:
            print(f"Creating label '{LABEL_NAME}'")
            repo.create_label(name=LABEL_NAME, color=LABEL_COLOR, description="PR needs correction")
        # add label to PR (issue is same number)
        issue.add_to_labels(LABEL_NAME)
        print(f"Label '{LABEL_NAME}' applied to PR #{pr_number}")
    except Exception as e:
        print(f"Failed to add/create label: {e}")

    # assign PR back to author (optional)
    try:
        issue.add_to_assignees(pr_author)
        print(f"Assigned PR to {pr_author}")
    except Exception as e:
        print(f"Failed to assign PR author: {e}")

    # exit non-zero? No: we already requested changes (that's enough). Exit 0.
    sys.exit(0)

else:
    # No violations -> you can optionally create an approval review or a check-run.
    print("No date format violations found.")
    try:
        # a neutral comment or approval can be created; here we do nothing.
        pass
    except Exception:
        pass
    sys.exit(0)
