
#!/usr/bin/env python3

import os
import json
from github import Github
from openai import OpenAI

# Initialize OpenAI client
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

PROMPT_DIR = ".github/prompts"


def load_prompts():
    prompts = {}
    for file in os.listdir(PROMPT_DIR):
        if file.endswith(".txt"):
            with open(os.path.join(PROMPT_DIR, file), "r") as f:
                prompts[file] = f.read()
    return prompts


def call_llm(prompt, content):
    final_prompt = prompt.replace("{content}", content)

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role": "user", "content": final_prompt}],
        temperature=0
    )

    return response.choices[0].message.content


def parse_response(output):
    try:
        return json.loads(output)
    except Exception:
        print("⚠️ Invalid JSON from LLM:", output)
        return []


def build_comments(issues, file_path):
    comments = []

    for issue in issues:
        if "line" not in issue:
            continue

        comments.append({
            "path": file_path,
            "line": issue["line"],
            "side": "RIGHT",
            "body": f"""
❌ **{issue.get('issue', 'Issue')}**

Text: `{issue.get('text', '')}`  
Suggestion: `{issue.get('suggestion', '')}`
"""
        })

    return comments


def main():
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(os.environ["GITHUB_REPOSITORY"])

    with open(os.environ["GITHUB_EVENT_PATH"]) as f:
        event = json.load(f)

    pr_number = event["pull_request"]["number"]
    pr = repo.get_pull(pr_number)

    prompts = load_prompts()
    all_comments = []

    for file in pr.get_files():
        if not file.patch:
            continue

        print(f"Reviewing file: {file.filename}")

        for prompt_name, prompt_text in prompts.items():
            print(f"  → Running prompt: {prompt_name}")

            output = call_llm(prompt_text, file.patch)
            issues = parse_response(output)

            comments = build_comments(issues, file.filename)
            all_comments.extend(comments)

    if all_comments:
        pr.create_review(
            body="🤖 AI Review (Grammar / Spelling / Date Checks)",
            event="COMMENT",
            comments=all_comments
        )
    else:
        print("✅ No issues found")


if __name__ == "__main__":
    main()
import re
from datetime import datetime
from base64 import b64decode

from github import Github, Auth


# ---------------- ENV VARIABLES ----------------

GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")

if not (GITHUB_EVENT_PATH and GITHUB_TOKEN and GITHUB_REPOSITORY):
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


# ---------------- TODAY DATE ----------------

today = datetime.utcnow()

if sys.platform == "win32":
    today_string = today.strftime("%B %#d, %Y")
else:
    today_string = today.strftime("%B %-d, %Y")


# ---------------- GITHUB CLIENT ----------------

gh = Github(auth=Auth.Token(GITHUB_TOKEN))
repo = gh.get_repo(GITHUB_REPOSITORY)
pull = repo.get_pull(pr_number)

print(f"Processing PR #{pr_number}")


# ---------------- HELPERS ----------------

def normalize_token(token):
    token = token.strip()
    token = " ".join(token.split())
    token = token.strip('"').strip("'")
    return token


# ---------------- PROCESS FILES ----------------

files = list(pull.get_files())

violations = {}

for f in files:

    # ignore deleted files
    if f.status == "removed":
        continue

    filename = f.filename

    if not filename.lower().endswith(".json"):
        continue

    print(f"Checking {filename}")

    raw = ""

    try:

        # Fetch file content using PR HEAD SHA (critical fix)
        head_sha = pull.head.sha

        content = repo.get_contents(filename, ref=head_sha)

        raw = b64decode(content.content).decode("utf-8", errors="ignore")

    except Exception as e:

        print(f"Fallback to patch for {filename}: {e}")

        raw = f.patch or ""

    if not raw:
        continue

    if filename not in violations:
        violations[filename] = []

    lines = raw.splitlines()

    for line_no, line in enumerate(lines, start=1):

        # -------- DATE FORMAT CHECK --------

        for match in date_candidate_pattern.finditer(line):

            token = normalize_token(match.group(0))

            if not allowed_date_regex.fullmatch(token):

                violations[filename].append(
                    f"LINE {line_no} : contains {token} which is not in format Month D, YYYY"
                )

        # -------- lastUpdate / x-modified CHECK --------

        key_match = re.search(r'"(lastUpdate|x-modified)"\s*:\s*"([^"]+)"', line)

        if key_match:

            key = key_match.group(1)
            value = normalize_token(key_match.group(2))

            if value != today_string:

                violations[filename].append(
                    f"LINE {line_no} : {key} has value {value} but must be today's date {today_string}"
                )


# ---------------- CREATE REVIEW ----------------

if violations:

    body_lines = []
    body_lines.append("Automated review: Date validation errors detected.\n")

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


    # ---------------- LABEL ----------------

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


    # ---------------- ASSIGN AUTHOR ----------------

    try:
        issue = repo.get_issue(pr_number)
        issue.add_to_assignees(pr_author)
    except:
        pass

    sys.exit(0)

else:

    print("No violations found")
    sys.exit(0)

