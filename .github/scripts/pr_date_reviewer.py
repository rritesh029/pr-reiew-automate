import os
import sys
import json
import re
from github import Github
from openai import OpenAI

# --- ENV ---
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

if not all([GITHUB_EVENT_PATH, GITHUB_TOKEN, GITHUB_REPOSITORY, GROQ_API_KEY]):
    print("Missing required environment variables")
    sys.exit(1)

# --- LOAD EVENT ---
with open(GITHUB_EVENT_PATH, "r") as f:
    event = json.load(f)

pr_dict = event.get("pull_request")
if not pr_dict:
    print("No PR found in event")
    sys.exit(0)

pr_number = pr_dict.get("number")

# --- INIT CLIENTS ---
g = Github(GITHUB_TOKEN)
repo = g.get_repo(GITHUB_REPOSITORY)
pr = repo.get_pull(pr_number)

client = OpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1"
)

PROMPT_DIR = ".github/prompts"


# --- LOAD PROMPTS ---
def load_prompts():
    prompts = {}
    for file in os.listdir(PROMPT_DIR):
        if file.endswith(".txt"):
            with open(os.path.join(PROMPT_DIR, file), "r") as f:
                prompts[file] = f.read()
    return prompts


# --- CALL GROQ ---
def call_llm(prompt, content):
    final_prompt = prompt.replace("{content}", content)

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "user",
                "content": final_prompt + "\n\nReturn ONLY valid JSON."
            }
        ],
        temperature=0
    )

    return response.choices[0].message.content


# --- PARSE JSON SAFELY ---
def parse_response(output):
    try:
        return json.loads(output)
    except:
        match = re.search(r'\[.*\]', output, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        print("Invalid JSON from LLM:\n", output)
        return []


# --- BUILD COMMENTS ---
def build_comments(issues, file_path):
    comments = []

    for issue in issues:
        line = issue.get("line")
        if not line:
            continue

        comments.append({
            "path": file_path,
            "line": line,
            "side": "RIGHT",
            "body": f"""❌ **{issue.get('issue', 'Issue')}**

Text: `{issue.get('text', '')}`
Suggestion: `{issue.get('suggestion', '')}`"""
        })

    return comments


# --- MAIN ---
def main():
    prompts = load_prompts()
    all_comments = []

    for file in pr.get_files():
        if not file.patch:
            continue

        for prompt_name, prompt_text in prompts.items():
            print(f"Running {prompt_name} on {file.filename}")

            output = call_llm(prompt_text, file.patch)
            issues = parse_response(output)

            comments = build_comments(issues, file.filename)
            all_comments.extend(comments)

    if all_comments:
        pr.create_review(
            body="🤖 AI Review (Groq)",
            event="COMMENT",
            comments=all_comments
        )
    else:
        print("No issues found")


if __name__ == "__main__":
    main()
