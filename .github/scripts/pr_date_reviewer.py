#!/usr/bin/env python3
"""
PR date format reviewer with inline comments (diff positions).

- Reads the GitHub event JSON (GITHUB_EVENT_PATH).
- Uses PyGithub to fetch PR and changed files.
- For each changed .json file, attempts to fetch file content from the PR head repo/ref.
  - If fetching full content fails (forks / permission / missing file), falls back to using the file.patch.
- Finds date tokens, validates them against allowed regex.
- For each violation tries to determine 'position' in the patch and create inline comment.
- If positions cannot be determined for some violations, they are included in the summary review body.
"""
import os
import sys
import json
import re
import yaml
from base64 import b64decode
from github import Github, Auth
from github.GithubException import UnknownObjectException, GithubException

# ---------- config / env ----------
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")  # "owner/repo"

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
    print("Missing required environment variables: GITHUB_EVENT_PATH, GITHUB_TOKEN, GITHUB_REPOSITORY")
    sys.exit(1)

# Load event payload
with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

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

allowed_regex_str = rules.get("allowed_date_regex") or \
    r'^(January|February|March|April|May|June|July|August|September|October|November|December) ([1-9]|[12][0-9]|3[01]), \d{4}$'
allowed_regex = re.compile(allowed_regex_str)

# Candidate date pattern to find tokens (broad capture)
date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b'
)

# ---------- helpers ----------
def find_positions_in_patch(patch_text: str, token: str):
    """
    Parse unified diff patch and return a list of positions where `token` is found.
    Each position is the diff 'position' integer (1-based within the file diff).
    Strategy:
      - iterate patch lines; for each hunk, count lines (pos counter starts at 0 at hunk start)
      - increment pos for every line in hunk (context ' ', added '+', removed '-')
      - when encounter a line that contains the token and is NOT a removed line (i.e. not starting with '-'),
        record the current pos (GitHub expects a 'position' pointing to a line in the diff)
    Returns list of positions (may be empty).
    """
    positions = []
    if not patch_text:
        return positions

    # Split patch into lines
    lines = patch_text.splitlines()
    pos = 0
    in_hunk = False

    for raw_line in lines:
        if raw_line.startswith('@@'):
            # new hunk header; reset pos counter for the hunk (per GitHub diff position semantics, positions
            # are counted per file diff from the start of the patch - resetting per hunk is OK as we restart counting)
            # We'll continue counting across hunks by not resetting global counting. But many implementations reset,
            # however serving per-hunk counting works if pos is the absolute count within the file patch used below.
            # To be safe, we continue counting across hunks (do not reset).
            in_hunk = True
            # Note: keep pos as-is (we want absolute position across the whole patch)
            continue
        if not in_hunk:
            continue
        # skip python diff metadata lines like "\ No newline at end of file"
        if raw_line.startswith('\\'):
            continue

        # increment pos for every line in hunk
        pos += 1
        # only consider lines that are in the new/visible file (not removed lines)
        line_type = raw_line[:1]  # one of ' ', '+', '-'
        content = raw_line[1:]
        # match token in content
        if token in content and line_type != '-':
            positions.append(pos)

    return positions

def safe_get_file_content(head_repo_obj, filename, head_ref, file_patch):
    """
    Try to fetch full file content from head repo at head_ref.
    If not available, return the file_patch (diff) as fallback.
    """
    try:
        content_file = head_repo_obj.get_contents(filename, ref=head_ref)
        raw = b64decode(content_file.content).decode("utf-8", errors="ignore")
        return raw, True  # True -> full content
    except UnknownObjectException:
        # not found at head ref (or permissions), fallback to patch
        return file_patch or "", False
    except GithubException as e:
        # API error, fallback to patch
        print(f"GitHub API error fetching {filename}: {e}. Falling back to patch if present.")
        return file_patch or "", False
    except Exception as e:
        print(f"Unexpected error fetching {filename}: {e}. Falling back to patch if present.")
        return file_patch or "", False

# ---------- main ----------
gh = Github(auth=Auth.Token(GITHUB_TOKEN))
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)  # PyGithub PullRequest object

print(f"Processing PR #{pr_number} by @{pr_author} in repo {GITHUB_REPOSITORY}")

files = list(pull.get_files())
print(f"Found {len(files)} changed file(s) in PR #{pr_number}.")

# collect inline comments and summary entries
inline_comments = []  # each item: dict(path, position, body)
summary_violations = []  # fallback messages for which we couldn't compute inline positions

for f in files:
    filename = f.filename
    if not filename.lower().endswith(".json"):
        continue

    print(f"Checking file: {filename}")
    # attempt to fetch file content or fallback to patch
    raw = ""
    try:
        head_ref = pull.head.ref
        head_repo_obj = pull.head.repo or repo
        raw_content, is_full = safe_get_file_content(head_repo_obj, filename, head_ref, f.patch)
        raw = raw_content or ""
        if is_full:
            print(f"Fetched full content for {filename} from {head_repo_obj.full_name}@{head_ref}")
        else:
            print(f"Using patch fallback for {filename}. (f.patch length: {len(f.patch or '')})")
    except Exception as e:
        print(f"Error fetching content for {filename}: {e}. Using patch fallback.")
        raw = f.patch or ""

    if not raw:
        print(f"No content available for {filename} (empty raw). Skipping.")
        continue

    # find candidate date tokens in raw content
    for match in date_candidate_pattern.finditer(raw):
        token = match.group(0).strip()

        # strict validate whole token against allowed regex
        if allowed_regex.match(token):
            continue  # token is fine

        # build comment body
        comment_body = (
            f"The date format `{token}` is not correct. Expected: `Month D, YYYY` "
            f"(example: `November 1, 2025`). Please fix this occurrence."
        )

        # try to compute positions in patch to add an inline comment
        positions = []
        if f.patch:
            positions = find_positions_in_patch(f.patch, token)

        if positions:
            # Create one inline comment per found position (GitHub allows multiple comments)
            for pos in positions:
                inline_comments.append({"path": filename, "position": pos, "body": comment_body})
                print(f"Queued inline comment for {filename} at position {pos} for token `{token}`")
        else:
            # couldn't compute a position (maybe file content matched but patch doesn't include context lines)
            summary_violations.append({"file": filename, "bad_date": token, "example": token})
            print(f"Could not determine inline position for token `{token}` in {filename}; added to summary.")

# If there are any comments -> create a REQUEST_CHANGES review with inline comments + summary (if any)
if inline_comments or summary_violations:
    # Build summary body for anything without inline position
    summary_lines = []
    if summary_violations:
        summary_lines.append("Automated review: Date format violations detected (unable to place inline comments for some):")
        summary_lines.append("")
        for v in summary_violations:
            summary_lines.append(f"- File `{v['file']}` contains date `{v['example']}` which is not allowed.")
        summary_lines.append("")
    summary_lines.append("Expected format: `Month D, YYYY` (e.g. `November 1, 2025`). Please fix all occurrences.")
    summary_body = "\n".join(summary_lines)

    # Build the 'comments' array expected by create_review
    comments_payload = []
    for c in inline_comments:
        comments_payload.append({
            "path": c["path"],
            "position": c["position"],
            "body": c["body"]
        })

    # If we have inline comments, include them; otherwise we'll create only summary top-level review
    try:
        if comments_payload:
            # create review with inline comments; include summary as body (if exists)
            pull.create_review(body=summary_body or "Automated date-format review", event="REQUEST_CHANGES", comments=comments_payload)
            print(f"Created REQUEST_CHANGES review with {len(comments_payload)} inline comment(s).")
        else:
            # only summary-level review
            pull.create_review(body=summary_body, event="REQUEST_CHANGES")
            print("Created REQUEST_CHANGES review (summary-level).")
    except Exception as e:
        print(f"Failed to create review: {e}")

    # create / apply label
    LABEL_NAME = "Correction Needed"
    LABEL_COLOR = "d93f0b"
    try:
        found_label = None
        for lab in repo.get_labels():
            if lab.name.lower() == LABEL_NAME.lower():
                found_label = lab
                break
        if not found_label:
            print(f"Creating label '{LABEL_NAME}'")
            repo.create_label(name=LABEL_NAME, color=LABEL_COLOR, description="PR needs correction")
        issue = repo.get_issue(pr_number)
        issue.add_to_labels(LABEL_NAME)
        print(f"Applied label '{LABEL_NAME}' to PR #{pr_number}.")
    except Exception as e:
        print(f"Failed to create/apply label: {e}")

    # assign PR to author
    try:
        issue = repo.get_issue(pr_number)
        if pr_author:
            issue.add_to_assignees(pr_author)
            print(f"Assigned PR #{pr_number} to @{pr_author}.")
    except Exception as e:
        print(f"Failed to assign PR to @{pr_author}: {e}")

    sys.exit(0)
else:
    print("No date format violations found.")
    sys.exit(0)
