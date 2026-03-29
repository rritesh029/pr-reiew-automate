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
