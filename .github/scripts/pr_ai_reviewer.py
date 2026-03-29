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


# ---------------- GROQ CLIENT ----------------

client = OpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1"
)


# ---------------- AI REVIEW FUNCTION ----------------

def ai_review(content):

    prompt = f"""
You are a strict PR reviewer.

Check the content for:
1. Date format issues (must be Month D, YYYY)
2. lastUpdate and x-modified must be today's date: {today_string}
3. Grammar mistakes
4. Spelling issues (Indian English)

Return ONLY JSON:

[
  {{
    "line": <line_number>,
    "issue": "<short issue>",
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
    except:
        raw = f.patch or ""

    if not raw:
        continue

    issues = ai_review(raw)

    if not issues:
        continue

    if filename not in violations:
        violations[filename] = []

    for issue in issues:
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
    body_lines.append("🤖 AI Review: Issues detected.\n")

    for file, errors in violations.items():

        if not errors:
            continue

        body_lines.append(f"{file.upper()}:")

        for err in errors:
            body_lines.append(err)

        body_lines.append("")

    review_body = "\n".join(body_lines)

    pull.create_review(
        body=review_body,
        event="REQUEST_CHANGES"
    )

    print("Review created")

    sys.exit(0)

else:

    print("No issues found")
    sys.exit(0)
