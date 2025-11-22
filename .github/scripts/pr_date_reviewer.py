#!/usr/bin/env python3
import os
import json
import re
import sys
import yaml
from base64 import b64decode
from github import Github
from github.GithubException import UnknownObjectException, GithubException

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

    raw = ""
    # Prefer to fetch from the PR head repository (handles forks)
    try:
        head_repo_obj = pull.head.repo or repo  # pull.head.repo may be None in some edge-cases
        head_ref = pull.head.ref  # branch name in head repo (e.g. "feature/branch")
    except Exception as e:
        print(f"Failed to read pull.head info: {e}")
        head_repo_obj = repo
        head_ref = None

    # Now attempt to fetch contents if we have a head_ref, else fallback to patch
    if head_ref:
        try:
            content_file = head_repo_obj.get_contents(filename, ref=head_ref)
            raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
            print(f"Fetched content for {filename} from {head_repo_obj.full_name}@{head_ref}")
        except UnknownObjectException:
            print(f"File {filename} not found at {head_repo_obj.full_name}@{head_ref}. Using patch fallback.")
            raw = f.patch or ""
        except GithubException as e:
            print(f"GitHub API error fetching {filename}: {e}. Using patch fallback.")
            raw = f.patch or ""
        except Exception as e:
            print(f"Unexpected error fetching {filename}: {e}. Using patch fallback.")
            raw = f.patch or ""
    else:
        # No head_ref available — fallback to patch
        raw = f.patch or ""
        print(f"No head_ref available for PR; using patch fallback for {filename}.")

    if not raw:
        print(f"No content available for {filename} (empty raw). Skipping.")
        continue

    # Find candidate date tokens and validate each token with allowed regex.
    # If token exists but doesn't match allowed_regex exactly, it's a violation.
    for match in date_candidate_pattern.finditer(raw):
        token = match.group(0).strip()
        # check strict match: whole token must match allowed regex
        if not allowed_regex.match(token):
            # record violation: include first occurrence location
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
    body = "\n".
