import os
import json
from github import Github
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def review_with_gpt(content):
    prompt = f"""
You are a strict PR content reviewer.

Check the following content for:
- Grammar mistakes
- Missing articles
- Sentence issues

Return JSON only.

Content:
\"\"\"{content}\"\"\"
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",   # cost-efficient + good enough
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    return response.choices[0].message.content


def main():
    g = Github(os.environ["GITHUB_TOKEN"])
    repo = g.get_repo(os.environ["GITHUB_REPOSITORY"])

    with open(os.environ["GITHUB_EVENT_PATH"]) as f:
        event = json.load(f)

    pr = repo.get_pull(event["pull_request"]["number"])

    for file in pr.get_files():
        if not file.patch:
            continue

        ai_output = review_with_gpt(file.patch)

        try:
            issues = json.loads(ai_output)
        except:
            print("Invalid JSON from GPT")
            continue

        comments = []
        for issue in issues:
            comments.append({
                "path": file.filename,
                "line": issue["line"],
                "side": "RIGHT",
                "body": f"""
❌ **{issue['issue']}**
Text: `{issue['text']}`
Suggestion: `{issue['suggestion']}`
"""
            })

        if comments:
            pr.create_review(
                body="AI Review Comments",
                event="COMMENT",
                comments=comments
            )


if __name__ == "__main__":
    main()
