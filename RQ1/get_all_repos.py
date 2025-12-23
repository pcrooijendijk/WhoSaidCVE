import requests
import os
import json
import time
import re
from dotenv import load_dotenv

START_DATE = "2025-01-01"
END_DATE   = "2025-08-01"   

INPUT_REPOS = "html_list.json"
OUTPUT_DIR = "repos_full_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

GRAPHQL_URL = "https://api.github.com/graphql"
PAGE_SIZE = 100
SLEEP = 0.35

load_dotenv()
KEYS = [os.getenv(f"KEY_{i}") for i in range(11) if os.getenv(f"KEY_{i}")]
token_index = 0

def headers():
    return {
        "Authorization": f"token {KEYS[token_index]}",
        "Content-Type": "application/json"
    }

def rotate_token():
    global token_index
    token_index = (token_index + 1) % len(KEYS)

PATTERNS = {
    "CVE": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "RUSTSEC": re.compile(r"\bRUSTSEC-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "PYSEC": re.compile(r"\bPYSEC-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "MAL": re.compile(r"\bMAL-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "OSV": re.compile(r"\bOSV-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "GSD": re.compile(r"\bGSD-\d{4}-\d{4,7}\b", re.IGNORECASE),

    "GHSA": re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "GO": re.compile(r"\bGO-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ASB": re.compile(r"\b(?:ASB|PUB)-A-\d{4}-\d{2}-\d{2}\b", re.IGNORECASE),

    "RHSA": re.compile(r"\bRH[SBA]-\d{4}:\d+\b", re.IGNORECASE),
    "ALSA": re.compile(r"\bAL[SBE]A-\d{4}:\d+\b", re.IGNORECASE),
    "RLSA": re.compile(r"\bR[LX]SA-\d{4}:\d+\b", re.IGNORECASE),

    "DEBIAN": re.compile(r"\b(?:DSA|DLA|DTSA)-\d{4,5}-\d{1,2}\b", re.IGNORECASE),
    "ALPINE": re.compile(r"\bALPINE-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "CURL": re.compile(r"\bCURL-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "MAGEIA": re.compile(r"\bMGASA-\d{4}-\d{3,5}\b", re.IGNORECASE),
    "SUSE": re.compile(r"\b(?:openSUSE|SUSE)-[A-Z]{2}-\d{4}:\d+\b", re.IGNORECASE),
    "UBUNTU": re.compile(r"\bUSN-\d{4}-\d{1,2}\b", re.IGNORECASE),

    "CWE": re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE),

    "ALPAQUITA": re.compile(r"\bBELL-CVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "BITNAMI": re.compile(r"\bBIT-kibana-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "CHAINGUARD": re.compile(r"\bCGA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "CRAN": re.compile(r"\b[HR]SEC-\d{4}-\d{1,2}\b", re.IGNORECASE),
    "ECHO": re.compile(r"\bECHO-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "JULIA": re.compile(r"\bJLSEC-\d{4}-\d{2,4}\b", re.IGNORECASE),
    "MINIMOS": re.compile(r"\bMINI-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE),
    "OPENEULER": re.compile(r"\bOESA-\d{4}-\d{4}\b", re.IGNORECASE),
}

def extract_ids(text):
    if not text:
        return {}
    found = {}
    for k, p in PATTERNS.items():
        hits = set(p.findall(text))
        if hits:
            found[k] = list(hits)
    return found

def graphql(query, variables):
    while True:
        r = requests.post(
            GRAPHQL_URL,
            json={"query": query, "variables": variables},
            headers=headers()
        )
        if r.status_code == 200:
            j = r.json()
            if "errors" in j:
                if any("rate limit" in e["message"].lower() for e in j["errors"]):
                    rotate_token()
                    time.sleep(1)
                    continue
            return j
        rotate_token()
        time.sleep(1)

def paginate(pr_id, field, subfield=None):
    results = []
    cursor = None

    while True:
        query = f"""
        query($id: ID!, $cursor: String) {{
            node(id: $id) {{
                ... on PullRequest {{
                {field}(first: {PAGE_SIZE}, after: $cursor) {{
                    pageInfo {{ hasNextPage endCursor }}
                    nodes {{
                    {subfield if subfield else "body author { login }"}
                    }}
                }}
                }}
            }}
        }}
        """
        res = graphql(query, {"id": pr_id, "cursor": cursor})
        block = res["data"]["node"][field]
        results.extend(block["nodes"])
        if not block["pageInfo"]["hasNextPage"]:
            break
        cursor = block["pageInfo"]["endCursor"]
        time.sleep(SLEEP)

    return results

def fetch_full_pr(pr_id):
    data = {"comments": [], "reviews": [], "review_threads": [], "commits": []}

    # PR comments
    data["comments"] = paginate(pr_id, "comments")

    # Reviews
    reviews = paginate(pr_id, "reviews", "body author { login }")
    for r in reviews:
        r["inline_comments"] = []
        if r.get("id"):
            r["inline_comments"] = paginate(r["id"], "comments")
    data["reviews"] = reviews

    # Review threads
    threads = paginate(pr_id, "reviewThreads", "comments(first: 100) { nodes { body author { login } } }")
    data["review_threads"] = threads

    # Commits
    commits = paginate(pr_id, "commits", "commit { message }")
    data["commits"] = commits

    return data

with open(INPUT_REPOS) as f:
    repos = json.load(f)

for url in repos:
    owner, name = url.rstrip("/").split("/")[-2:]
    print(f"Processing {owner}/{name}")

    cursor = None
    all_prs = []

    while True:
        pr_query = """
        query($owner: String!, $name: String!, $cursor: String) {
            repository(owner: $owner, name: $name) {
                pullRequests(first: 50, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes {
                    id
                    number
                    title
                    body
                    createdAt
                    updatedAt
                    url
                }
                }
            }
        }
        """
        res = graphql(pr_query, {"owner": owner, "name": name, "cursor": cursor})
        prs = res["data"]["repository"]["pullRequests"]

        for pr in prs["nodes"]:
            if not (
                START_DATE <= pr["createdAt"] < END_DATE or
                START_DATE <= pr["updatedAt"] < END_DATE
            ):
                continue

            full = fetch_full_pr(pr["id"])
            pr["full"] = full

            # Extract IDs
            pr["security_mentions"] = []
            def scan(text, src):
                ids = extract_ids(text)
                for t, vals in ids.items():
                    for v in vals:
                        pr["security_mentions"].append({
                            "type": t,
                            "id": v,
                            "source": src
                        })

            scan(pr["title"], "title")
            scan(pr["body"], "body")
            for c in full["comments"]:
                scan(c["body"], "comment")
            for r in full["reviews"]:
                scan(r.get("body"), "review")
                for ic in r.get("inline_comments", []):
                    scan(ic["body"], "inline_review")
            for c in full["commits"]:
                scan(c["commit"]["message"], "commit")

            all_prs.append(pr)

        if not prs["pageInfo"]["hasNextPage"]:
            break
        cursor = prs["pageInfo"]["endCursor"]
        time.sleep(1)

    out_file = f"{OUTPUT_DIR}/{owner}_{name}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_prs, f, indent=2, ensure_ascii=False)
