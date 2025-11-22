#!/usr/bin/env python3
"""PR date format reviewer

This script reads the GitHub event JSON (path provided by --event-path)
and a YAML rule file describing a regex to validate the PR title.

Exit codes:
  0 - title matches rule
  1 - title does not match rule or an error occurred
"""
import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None


def load_event(path: Path):
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def load_rule(path: Path):
    if yaml is None:
        raise RuntimeError('PyYAML is required. Install with `pip install PyYAML`')
    with path.open('r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def main():
    p = argparse.ArgumentParser(description='Validate PR title date format')
    p.add_argument('--event-path', required=True, help='Path to GitHub event JSON')
    p.add_argument('--rule-file', required=True, help='YAML file with `rule.pattern`')
    args = p.parse_args()

    event_path = Path(args.event_path)
    rule_path = Path(args.rule_file)

    if not event_path.exists():
        print(f'ERROR: event file not found: {event_path}', file=sys.stderr)
        sys.exit(1)

    if not rule_path.exists():
        print(f'ERROR: rule file not found: {rule_path}', file=sys.stderr)
        sys.exit(1)

    try:
        event = load_event(event_path)
    except Exception as exc:
        print(f'ERROR: failed to load event JSON: {exc}', file=sys.stderr)
        sys.exit(1)

    try:
        rule = load_rule(rule_path)
    except Exception as exc:
        print(f'ERROR: failed to load rule file: {exc}', file=sys.stderr)
        sys.exit(1)

    pr = event.get('pull_request') or event.get('pull_request', {})
    title = None
    if pr and isinstance(pr, dict):
        title = pr.get('title')
    if not title:
        # fallback: check issue.title (some events)
        issue = event.get('issue')
        if issue and isinstance(issue, dict):
            title = issue.get('title')

    if not title:
        print('ERROR: could not find PR/issue title in event payload', file=sys.stderr)
        sys.exit(1)

    pattern = None
    # rule can be nested under 'rule' key
    if isinstance(rule, dict):
        if 'rule' in rule and isinstance(rule['rule'], dict):
            pattern = rule['rule'].get('pattern')
        else:
            pattern = rule.get('pattern')

    if not pattern:
        print('ERROR: no `pattern` found in rule file', file=sys.stderr)
        sys.exit(1)

    try:
        regex = re.compile(pattern)
    except re.error as exc:
        print(f'ERROR: invalid regex pattern: {exc}', file=sys.stderr)
        sys.exit(1)

    if regex.search(title):
        print(f'OK: PR title matches date pattern: "{title}"')
        sys.exit(0)
    else:
        # show user-friendly guidance from rule if available
        description = None
        if isinstance(rule, dict):
            r = rule.get('rule') or rule
            if isinstance(r, dict):
                description = r.get('description')
        print('FAIL: PR title does not match required date format.', file=sys.stderr)
        if description:
            print(f'Expected: {description}', file=sys.stderr)
        print(f'Actual title: "{title}"', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
