#!/usr/bin/env python3

import os
import sys
import json
import re
from datetime import datetime
from base64 import b64decode

from github import Github, Auth
from openai import OpenAI


# ---------------- ENV ----------------

GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

if not all([GITHUB_EVENT_PATH, GITHUB_TOKEN, GITHUB_REPOSITORY, GROQ_API_KEY]):
    print("Missing required environment variables")
    sys.exit(1)


# ---------------- LOAD EVENT ----------------

with open(GITHUB_EVENT_PATH) as f:
    event = json.load(f)

pr_dict = event.get("pull_request")
if not pr_dict:
    sys.exit(0)

pr_number = pr_dict["number"]
pr_author = pr_dict["user"]["login"]


# ---------------- DATE RULES (KEEP ORIGINAL) ----------------

allowed_date_regex = re.compile(
    r'^(January|February|March|April|May|June|July|August|September|October|November|December) (?:[1-9]|[12][0-9]|3[01]), \d{4}$'
)

date_candidate_pattern = re.compile(
    r'\b('
    r'January|February|March|April|May|June|July|August|September|October|November|December'
    r'|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
    r')\s+([0-9]{1,2}),\s+([0-9]{4})\b',
    re.IGNORECASE
)


# ---------------- TODAY DATE ----------------

today = datetime.utcnow()

if sys.platform == "win32":
    today_string = today.strftime("%B %#d, %Y")
else:
    today_string = today.strftime("%B %-d, %Y")


# ---------------- GITHUB ----------------

gh = Github(auth=Auth.Token(GITHUB_TOKEN))
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)

print(f"Processing PR #{pr_number}")


# ---------------- GROQ CLIENT ----------------

client = OpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1"
)


# ---------------- HELPERS ----------------

def normalize_token(token):
    token = token.strip()
    token = " ".join(token.split())
    token = token.strip('"').strip("'")
    return token


# ---------------- AI REVIEW (ONLY LANGUAGE) ----------------

def ai_review(content):

    prompt = f"""
You are a strict language reviewer.

Check ONLY for:
1. Grammar mistakes
2. Sentence issues
3. Spelling issues

Rules:
- Use Indian English (colour, centre are correct)
- DO NOT check dates
- DO NOT modify numbers or dates

Return ONLY JSON:

[
  {{
    "line": <line_number>,
    "issue": "<grammar/spelling>",
    "text": "<problem>",
    "suggestion": "<fix>"
  }}
]

Content:
\"\"\"{content}\"\"\"
"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    output = response.choices[0].message.content

    try:
        return json.loads(output)
    except:
        match = re.search(r'\[.*\]', output, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        print("Invalid AI response:", output)
        return []


# ---------------- PROCESS FILES ----------------

files = list(pull.get_files())
violations = {}

for f in files:

    if f.status == "removed":
        continue

    filename = f.filename

    if not filename.lower().endswith(".json"):
        continue

    print(f"Checking {filename}")

    raw = ""

    try:
        content = repo.get_contents(filename, ref=pull.head.sha)
        raw = b64decode(content.content).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Fallback to patch for {filename}: {e}")
        raw = f.patch or ""

    if not raw:
        continue

    if filename not in violations:
        violations[filename] = []

    lines = raw.splitlines()

    # ---------------- REGEX DATE VALIDATION ----------------

    for line_no, line in enumerate(lines, start=1):

        for match in date_candidate_pattern.finditer(line):

            token = normalize_token(match.group(0))

            if not allowed_date_regex.fullmatch(token):
                violations[filename].append(
                    f"LINE {line_no} : contains {token} which is not in format Month D, YYYY"
                )

        key_match = re.search(r'"(lastUpdate|x-modified)"\s*:\s*"([^"]+)"', line)

        if key_match:
            key = key_match.group(1)
            value = normalize_token(key_match.group(2))

            if value != today_string:
                violations[filename].append(
                    f"LINE {line_no} : {key} has value {value} but must be today's date {today_string}"
                )

    # ---------------- AI LANGUAGE VALIDATION ----------------

    ai_issues = ai_review(raw)

    for issue in ai_issues:
        line = issue.get("line", "?")
        msg = issue.get("issue", "")
        text = issue.get("text", "")
        suggestion = issue.get("suggestion", "")

        violations[filename].append(
            f"LINE {line} : {msg} → `{text}` | Suggestion: `{suggestion}`"
        )


# ---------------- CREATE REVIEW ----------------

if violations:

    body_lines = []
    body_lines.append("🤖Combined Review: Date + Language Issues\n")

    for file, errors in violations.items():

        if not errors:
            continue

        body_lines.append(f"{file.upper()}:")

        for err in errors:
            body_lines.append(err)

        body_lines.append("")

    review_body = "\n".join(body_lines)

    try:
        pull.create_review(
            body=review_body,
            event="REQUEST_CHANGES"
        )
        print("Review created")

    except Exception as e:
        print(f"Review creation failed: {e}")

    sys.exit(0)

else:
    print("No violations found")
    sys.exit(0)
