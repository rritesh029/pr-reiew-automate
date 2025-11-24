#!/usr/bin/env python3
"""
Robust PR date format reviewer (updated).

- Reads the GitHub event JSON (GITHUB_EVENT_PATH).
- Uses PyGithub to fetch PR and changed files.
- For each changed .json file, attempts to fetch file content from the PR head repo/ref.
  - If fetching full content fails (forks / permission / missing file), falls back to using the file.patch.
- Detects date-like tokens (full month names + common 3-letter abbreviations).
- Normalizes tokens and validates each against the allowed regex loaded from rules.
- If violations exist: creates a REQUEST_CHANGES review, adds "Correction Needed" label (creates if missing),
  and assigns the PR author.
"""

import os
import sys
import json
import re
import yaml
from base64 import b64decode

from github import Github, GithubException, Auth
from github.GithubException import UnknownObjectException

# --- env / config
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
# "owner/repo"

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables: GITHUB_EVENT_PATH, GITHUB_TOKEN, GITHUB_REPOSITORY")
    sys.exit(1)

# Load event payload
try:
    with open(GITHUB_EVENT_PATH, "r") as f:
        event = json.load(f)
except Exception as e:
    print(f"Failed to load event payload from {GITHUB_EVENT_PATH}: {e}")
    sys.exit(1)

# Only proceed for pull_request events
pr_dict = event.get("pull_request")
if not pr_dict:
    print("No 'pull_request' object in event payload. Exiting.")
    sys.exit(0)

pr_number = pr_dict.get("number")
pr_author = pr_dict.get("user", {}).get("login")
if not pr_number:
    print("PR number not found in payload. Exiting.")
    sys.exit(1)

# Load rules (yaml)
RULE_PATH = ".github/pr-rules/date_format.yml"
try:
    with open(RULE_PATH, "r") as rf:
        rules = yaml.safe_load(rf) or {}
except FileNotFoundError:
    print(f"Rule file {RULE_PATH} not found — using default regex.")
    rules = {}
except Exception as e:
    print(f"Error loading rule file {RULE_PATH}: {e}. Using default regex.")
    rules = {}

# Default allowed regex (same semantics as your original)
default_allowed_regex = r'^(January|February|March|April|May|June|July|August|September|October|November|December) (?:[1-9]|[12][0-9]|3[01]), \d{4}$'

# Use the YAML-provided regex if present, otherwise fallback
allowed_regex_str = rules.get("allowed_date_regex") or default_allowed_regex

# Compile allowed regex. Use UNICODE to be explicit.
try:
    allowed_regex = re.compile(allowed_regex_str, flags=re.UNICODE)
except re.error as e:
    print(f"Failed to compile allowed_date_regex from rules: {e}. Falling back to default regex.")
    allowed_regex = re.compile(default_allowed_regex, flags=re.UNICODE)

# Candidate date pattern to find tokens (broad capture)
# This pattern captures full month names (January...) and common 3-letter abbreviations (Jan, Feb, ...).
# It will catch tokens like "November 01, 2025", "Nov 1, 2025", etc., so we can validate them and report violations.
date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r'|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b',
    flags=re.IGNORECASE | re.UNICODE
)

# Initialize PyGithub (use new auth style)
gh = Github(auth=Auth.Token(GITHUB_TOKEN))
try:
    repo = gh.get_repo(GITHUB_REPOSITORY)
except Exception as e:
    print(f"Failed to open repository {GITHUB_REPOSITORY}: {e}")
    sys.exit(1)

try:
    pull = repo.get_pull(pr_number)  # PyGithub PullRequest object
except Exception as e:
    print(f"Failed to fetch PR #{pr_number} from repo {GITHUB_REPOSITORY}: {e}")
    sys.exit(1)

print(f"Processing PR #{pr_number} by @{pr_author} in repo {GITHUB_REPOSITORY}")

# Gather changed files via pull.get_files()
try:
    files = list(pull.get_files())
except Exception as e:
    print(f"Failed to list files for PR #{pr_number}: {e}")
    files = []

print(f"Found {len(files)} changed file(s) in PR #{pr_number}.")

violations = []

def normalize_token(tok: str) -> str:
    """
    Normalize whitespace and strip surrounding quotes if any.
    Collapses multiple whitespace into single spaces.
    """
    tok = tok.strip()
    # Collapse all whitespace (including NBSP etc.) to single space
    tok = " ".join(tok.split())
    # Remove surrounding double/single quotes if present (defensive)
    if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
        tok = tok[1:-1].strip()
    return tok

for f in files:
    filename = f.filename
    if not filename.lower().endswith(".json"):
        # skip non-json
        continue

    print(f"Checking file: {filename}")

    raw = ""
    # Determine head repo/ref to fetch content (handles forks)
    try:
        head_ref = pull.head.ref  # branch name in the head repo
        head_repo_obj = pull.head.repo  # Repository object for the head (may be None in weird cases)
        if head_repo_obj is None:
            print("pull.head.repo is None, defaulting to base repo.")
            head_repo_obj = repo
        try:
            content_file = head_repo_obj.get_contents(filename, ref=head_ref)
            # content is base64 encoded
            raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
            print(f"Fetched full content for {filename} from {head_repo_obj.full_name}@{head_ref}")
        except UnknownObjectException:
            # File may not exist at that path in head ref or permissions; fallback to patch
            print(f"get_contents returned 404 for {filename} in {head_repo_obj.full_name}@{head_ref}; using patch fallback.")
            raw = f.patch or ""
        except GithubException as e:
            print(f"GitHub API error fetching content for {filename}: {e}. Using patch fallback if available.")
            raw = f.patch or ""
        except Exception as e:
            print(f"Unexpected error when fetching {filename}: {e}. Using patch fallback if available.")
            raw = f.patch or ""
    except Exception as e:
        print(f"Error preparing to fetch {filename}: {e}. Using patch fallback if available.")
        raw = f.patch or ""

    if not raw:
        print(f"No content available for {filename} (empty raw). Skipping.")
        continue

    # Search for date tokens and validate each found token
    for match in date_candidate_pattern.finditer(raw):
        token = match.group(0)
        token_norm = normalize_token(token)

        # Validate using fullmatch to require the entire token match the allowed regex
        # (safer than .match which may allow prefix matches)
        if not allowed_regex.fullmatch(token_norm):
            violations.append({"file": filename, "bad_date": token_norm})
            print(f"Violation found in {filename}: {token_norm}")
        else:
            # optional: debug print allowed tokens
            print(f"Allowed date found in {filename}: {token_norm}")

# If violations: create review, add label, assign
if violations:
    # Build the review body
    lines = []
    lines.append("Automated review: Date format violations detected.")
    lines.append("")
    for v in violations:
        lines.append(f"- File `{v['file']}` contains date `{v['bad_date']}` which is not in allowed format.")
    lines.append("")
    lines.append("Expected format: `Month D, YYYY` (e.g. `November 1, 2025`). Please fix all occurrences.")
    body = "\n".join(lines)

    print("Creating a REQUEST_CHANGES review...")
    try:
        # Create a review (summary-level). For inline comments you can build a 'comments' array with path/position.
        pull.create_review(body=body, event="REQUEST_CHANGES")
        print("Review created (REQUEST_CHANGES).")
    except Exception as e:
        print(f"Failed to create review: {e}")

    # Add label (create if not present)
    LABEL_NAME = "Correction Needed"
    LABEL_COLOR = "d93f0b"
    try:
        existing = None
        for lab in repo.get_labels():
            if lab.name.lower() == LABEL_NAME.lower():
                existing = lab
                break
        if not existing:
            print(f"Label '{LABEL_NAME}' not found; creating it.")
            try:
                repo.create_label(name=LABEL_NAME, color=LABEL_COLOR, description="PR needs correction")
            except Exception as e:
                print(f"Failed to create label '{LABEL_NAME}': {e}")
        # apply label to the PR (issues API)
        try:
            issue = repo.get_issue(pr_number)
            issue.add_to_labels(LABEL_NAME)
            print(f"Applied label '{LABEL_NAME}' to PR #{pr_number}.")
        except Exception as e:
            print(f"Failed to apply label '{LABEL_NAME}' to PR #{pr_number}: {e}")
    except Exception as e:
        print(f"Failed to create/apply label '{LABEL_NAME}': {e}")

    # Assign PR back to author
    try:
        issue = repo.get_issue(pr_number)
        if pr_author:
            try:
                issue.add_to_assignees(pr_author)
                print(f"Assigned PR #{pr_number} to @{pr_author}.")
            except Exception as e:
                print(f"Failed to assign PR to @{pr_author}: {e}")
    except Exception as e:
        print(f"Failed to fetch issue for PR #{pr_number} to assign: {e}")

    # Exit 0 (we created a review so no need to fail the job)
    sys.exit(0)
else:
    print("No date format violations found.")
    # Optionally you can create an APPROVE review here
    sys.exit(0)
