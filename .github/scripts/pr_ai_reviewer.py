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


# ---------------- DATE RULES ----------------

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


# ---------------- TODAY ----------------

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


def extract_sentences(lines):
    """
    Extract only meaningful sentence-like string values from JSON lines
    """
    results = []

    for i, line in enumerate(lines, start=1):

        matches = re.findall(r':\s*"([^"]+)"', line)

        for text in matches:

            text = text.strip()

            # Skip pure date tokens
            if date_candidate_pattern.fullmatch(text):
                continue

            # Skip very small strings
            if len(text) < 5:
                continue

            # Skip key-like / structured values
            if ":" in text and len(text.split()) < 3:
                continue

            results.append((i, text))

    return results


# ---------------- AI REVIEW ----------------

def ai_review(text):

    prompt = f"""
You are a strict grammar reviewer.

ONLY check natural English sentences.

STRICTLY IGNORE:
- Dates (any format)
- Numbers
- JSON key-value pairs

DO NOT suggest changes to:
- Dates
- Numeric values

Use Indian English.

If no real issue → return []

Return ONLY JSON:
[
  {{
    "issue": "grammar/spelling",
    "text": "...",
    "suggestion": "..."
  }}
]

Text:
\"\"\"{text}\"\"\"
"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    output = response.choices[0].message.content

    try:
        data = json.loads(output)
    except:
        match = re.search(r'\[.*\]', output, re.DOTALL)
        if match:
            data = json.loads(match.group(0))
        else:
            return []

    clean = []
    for item in data:
        if item["text"].strip() != item["suggestion"].strip():
            clean.append(item)

    return clean


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

    try:
        content = repo.get_contents(filename, ref=pull.head.sha)
        raw = b64decode(content.content).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Fallback to patch for {filename}: {e}")
        raw = f.patch or ""

    if not raw:
        continue

    lines = raw.splitlines()
    violations[filename] = []

    # ---------------- VALIDATE JSON (avoid duplicate garbage) ----------------

    try:
        json.loads(raw)
    except Exception as e:
        print(f"Skipping invalid JSON in {filename}: {e}")
        continue

    # ---------------- DATE VALIDATION ----------------

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

    sentences = extract_sentences(lines)

    for line_no, text in sentences:

        issues = ai_review(text)

        for issue in issues:
            violations[filename].append(
                f"LINE {line_no} : {issue['issue']} → `{issue['text']}` | Suggestion: `{issue['suggestion']}`"
            )


# ---------------- CREATE REVIEW ----------------

if violations:

    body = ["🤖 Combined Review: Date + Language Issues\n"]

    for file, errs in violations.items():

        if not errs:
            continue

        body.append(f"{file.upper()}:")

        for e in errs:
            body.append(e)

        body.append("")

    review_body = "\n".join(body)

    try:
        pull.create_review(
            body=review_body,
            event="REQUEST_CHANGES"
        )
        print("Review created")

    except Exception as e:
        print(f"Review failed: {e}")

    sys.exit(0)

else:
    print("No violations found")
    sys.exit(0)
