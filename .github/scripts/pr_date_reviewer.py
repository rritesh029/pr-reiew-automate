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

# Make the candidate detector permissive (catch any Word D, YYYY)
date_candidate_pattern = re.compile(r'\b([A-Za-z]+)\s+([0-9]{1,2}),\s+([0-9]{4})\b')

# --- helper to compute line number ---
def find_line_number_in_full_content(content: str, token: str):
    """
    Return 1-based line number of the first line in content that contains token.
    """
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if token in line:
            return i + 1
    return None

def find_line_number_in_patch(patch: str, token: str):
    """
    Parse unified diff patch and return the 1-based line number in the new file where token first appears.
			 
												 
														
																				
																											  
    """
    if not patch:
        return None
    new_line_num = None
    for raw_line in patch.splitlines():
        if raw_line.startswith('@@'):
							   
									  
            try:
                header = raw_line
                parts = header.split()
												 
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

        # consider only lines present in the new file (space ' ' or added '+')
        if token in content and line_type != '-':
            return new_line_num

																		   
        if line_type in (' ', '+'):
            new_line_num += 1
											   

    return None

# normalize token helper
def normalize_token_for_matching(token: str) -> str:
    t = token.strip()
    t = t.replace('\u00A0', ' ')
    # remove zero-width and directionality chars
    t = re.sub(r'[\u200B\u200C\u200D\u200E\u200F]', '', t)
    t = re.sub(r'\s+', ' ', t)
    return t

# iterate changed files
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

    for match in date_candidate_pattern.finditer(raw):
        token_orig = match.group(0).strip()
        # normalize token before matching against allowed regex
        token_norm = normalize_token_for_matching(token_orig)

        # use fullmatch to ensure entire token matches pattern
        is_allowed = bool(allowed_regex.fullmatch(token_norm))

        if not is_allowed:
            # compute line number: try to find the original token first, fallback to normalized token
            line_no = None
            try:
                if is_full_content:
                    line_no = find_line_number_in_full_content(raw, token_orig)
                    if line_no is None and token_norm != token_orig:
                        line_no = find_line_number_in_full_content(raw, token_norm)
                else:
                    line_no = find_line_number_in_patch(raw, token_orig)
                    if line_no is None and token_norm != token_orig:
                        line_no = find_line_number_in_patch(raw, token_norm)
            except Exception as e:
                print(f"Error computing line number for token {token_orig} in {filename}: {e}")
                line_no = None

            violations.append({
                "file": filename,
                "bad_date": token_orig,
                "line": line_no
            })
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
