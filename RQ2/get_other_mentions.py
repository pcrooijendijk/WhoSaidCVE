import requests
import pandas as pd
import time
import os
import re
import json
from dotenv import load_dotenv
from datetime import datetime
from typing import List, Dict
import argparse

START_DATE_SEARCH = "2025-01-01"
END_DATE_SEARCH = "2025-08-01"
REST_API_URL = "https://api.github.com/search/issues"
GRAPHQL_API_URL = "https://api.github.com/graphql"

# Loading the GitHub keys
load_dotenv()
KEYS = [os.getenv(f"KEY_{i}") for i in range(11)]
KEY_INDEX = 0

# Retrieving the Bot names to search for their names in the PRs
with open("bots.txt", "r") as f: 
    bot_names = [s.rstrip() for s in f.readlines()]

extra_names = ["pensarapp", "pull", "bot", "dependabot", "renovate", "cycode", "github-actions", "guardrails", "snyk", "coderabbit", "copilot-pull-request-reviewer[bot]", "cursor[bot]", "github-advanced-security[bot]"]
for name in extra_names:
    bot_names.append(name)

# Helper function for GitHub authentication
def get_header():
    return {
        'Authorization': f'token {KEYS[KEY_INDEX]}',
        'Accept': 'application/vnd.github.v3+json',
    }

# Rotating to another key if the rate limit is exceeded
def rotate_key():
    global KEY_INDEX
    KEY_INDEX = (KEY_INDEX + 1) % len(KEYS)
    return get_header()

# Determining if the user is either an agent, human or bot
def get_user_type(login):
    if not login: 
        return "Unknown"
    login = login.lower()
    if "copilot" in login or "devin" in login or "chatgpt" in login: # Search for Copilot and Devin
        return "Agent"
    if any(bot_name in login for bot_name in bot_names): # Search if the login name is in the bot list
        return "Bot"
    return "Human" # Otherwise return that the user is human

# Helper function to determine if there are other users active in a pull request
def get_other_bots(participants, exclude_login):
    bots = set()
    for p in participants:
        if p and p != exclude_login:
            if get_user_type(p) in ['Bot', 'Agent']:
                bots.add(p)
    return ", ".join(list(bots))

def search_page_rest(query, page):
    params = {"q": query, "per_page": 100, "page": page}
    while True:
        try:
            r = requests.get(REST_API_URL, headers=get_header(), params=params)
            if r.status_code == 403 or (r.status_code == 200 and "RATE_LIMITED" in r.text):
                rotate_key()
                time.sleep(2)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"  [Error in Search] {e}")
            time.sleep(5)

def search_with_date_split(id, start_date, end_date) -> List[Dict]:
    # Looking for the IDs in PRs when they where updated within the timeframe
    query = f'{id} is:pr updated:{start_date}..{end_date}'
    
    first_page = search_page_rest(query, 1)
    total_count = first_page.get("total_count", 0)
    
    results = []

    if total_count < 1000:
        if total_count > 0:
            # Summing up the results to show in the terminal if any PRs where found
            print(f" -> Range {start_date} to {end_date}: Found {total_count} PRs.")
        results.extend(first_page.get("items", []))
        
        pages = (total_count // 100) + 1
        for p in range(2, pages + 1):
            data = search_page_rest(query, p)
            results.extend(data.get("items", []))
        return results

    # Splitting the pull requests if there are too many (GitHub restrictions)
    print(f"    -> Range {start_date} to {end_date}: Found {total_count} total PRs.")
    s_dt = datetime.fromisoformat(start_date)
    e_dt = datetime.fromisoformat(end_date)
    mid_dt = s_dt + (e_dt - s_dt) / 2
    mid_date_str = mid_dt.date().isoformat()
    
    return (
        search_with_date_split(id, start_date, mid_date_str) + 
        search_with_date_split(id, mid_date_str, end_date)
    )

# The GraphQL query used for getting the PRs 
graphql_pr_query = """
query($owner: String!, $name: String!, $number: Int!) {
    repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
            url
            title
            state
            merged
            createdAt
            author { login }
            body
            comments_count: comments { totalCount }
            reviews_count: reviews { totalCount }
            
            comments(first: 50) { nodes { body author { login } } }
            
            reviews(first: 20) { 
                nodes { 
                    body 
                    author { login } 
                    comments(first: 10) { nodes { body author { login } } } 
                } 
            }
            
            reviewThreads(first: 20) { 
                nodes { 
                    comments(first: 10) { nodes { body author { login } } } 
                } 
            }
            
            commits(first: 50) {
                nodes {
                    commit {
                        message
                        author { user { login } }
                    }
                }
            }
        }
    }
}
"""

def analyze_single_pr_graphql(owner, name, number, cve_id_target, pattern_target):
    variables = {"owner": owner, "name": name, "number": number}
    
    while True:
        try:
            r = requests.post(GRAPHQL_API_URL, headers=get_header(), json={'query': graphql_pr_query, 'variables': variables})
            
            if r.status_code == 403 or (r.status_code == 200 and "RATE_LIMITED" in r.text):
                # Rotate the key when the status code is 403, meaning that current key is out of requests
                rotate_key()
                time.sleep(1)
                continue
            
            if r.status_code == 200:
                # Retrieve the data and process this PR with the GraphQL query
                json_data = r.json()
                if 'errors' in json_data: 
                    return []
                return process_pr_node(owner + '/' + name, json_data['data']['repository']['pullRequest'], cve_id_target, pattern_target)
            else:
                print(f"GraphQL Error {r.status_code}")
                time.sleep(5)
        except Exception as e:
            print(f"Exception in GraphQL: {e}")
            return []

def process_pr_node(repo_name, pr, cve_id_target, pattern_target):
    if not pr: 
        return [] # Returning empty list when the PR is emtpy
    
    rows = []
    
    # Getting the information about the author, state and total comments
    pr_url = pr['url']
    state = "Merged" if pr['merged'] else pr['state'].capitalize()
    author_login = pr['author']['login'] if pr['author'] else "Ghost"
    total_comments = pr['comments_count']['totalCount'] + pr['reviews_count']['totalCount']
    participants = set()
    if author_login != "Ghost": # Checking if the author is a "ghost"
        participants.add(author_login)

    mentions = []

    # Helper function for scanning the text to search for specific IDs
    def scan_text(text, source_type, user_login):
        if pd.isna(text) or not isinstance(text, str): return
        
        matches = pattern_target.findall(text)
        if matches:
            if user_login != "Ghost": 
                participants.add(user_login)
            u_type = get_user_type(user_login)
            unique_matches = list(set([m.upper() for m in matches]))
            
            for m in unique_matches:
                mentions.append({
                    "ID": m, 
                    "Source": source_type, 
                    "Mentioner": user_login, 
                    "Mentioner_Type": u_type
                })

    # Searching in the title and body of the PR
    scan_text(pr.get('title', ""), "PR Title", author_login)
    scan_text(pr.get('body', ""), "PR Body", author_login)
    
    # Searching in the comments of the PR
    if pr['comments']['nodes']:
        for comm in pr['comments']['nodes']:
            if comm and comm['author']: scan_text(comm['body'], "PR Comment", comm['author']['login'])
    
    # Searching in the reviews of the PR
    if pr['reviews']['nodes']:
        for review in pr['reviews']['nodes']:
            if review and review['author']:
                scan_text(review['body'], "Review Summary", review['author']['login'])
                if review['comments']['nodes']:
                    for inline in review['comments']['nodes']:
                        if inline and inline['author']: scan_text(inline['body'], "Inline Code Comment", inline['author']['login'])

    # Searching in the inlien review comments of the PR
    if pr['reviewThreads']['nodes']:
        for thread in pr['reviewThreads']['nodes']:
            if thread['comments']['nodes']:
                for comm in thread['comments']['nodes']:
                    if comm and comm['author']: scan_text(comm['body'], "Inline Review Comment", comm['author']['login'])
    
    # Searching in the commits of the PR
    if pr['commits']['nodes']:
        for c_node in pr['commits']['nodes']:
            commit = c_node['commit']
            if commit['message']:
                committer = "Ghost"
                if commit['author'] and commit['author']['user'] and commit['author']['user']['login']:
                    committer = commit['author']['user']['login']
                scan_text(commit['message'], "Commit Message", committer)

    # If there where no mentions found, then classify it as a search match
    if not mentions:
        mentions.append({
            "ID": cve_id_target,
            "Type": "CVE",
            "Source": "Code/Diff (Search Match)",
            "Mentioner": author_login, 
            "Mentioner_Type": get_user_type(author_login)
        })

    # Make the final rows
    for m in mentions:
        rows.append({
            "Repository": repo_name, 
            "ID": m['ID'],
            "URL": pr_url,
            "PR_State": state,
            "Total_Comments": total_comments,
            "Mentioner": m['Mentioner'],
            "Mentioner_Type": m['Mentioner_Type'],
            "Source": m['Source'],
            "Other_Bots": get_other_bots(participants, m['Mentioner'])
        })
    
    return rows

# Helper function to save the pandas dataframe to a csv file
def save_to_csv(data, filename):
    df = pd.DataFrame(data)
    if not os.path.isfile(filename):
        df.to_csv(filename, index=False)
    else:
        df.to_csv(filename, mode='a', header=False, index=False)

def main(id: str, author: str):
    # Load IDs from file
    with open("all_ids.json", "r") as f: 
        all_ids = json.load(f)
    
    target_ids = []
    for cve in all_ids[id][author]:
        target_ids.append(cve)

    print(f"Loaded {len(target_ids)} IDs to process.")

    # Outer loop over IDs
    for idx, current_id in enumerate(target_ids):
        print(f"Currently Processing: {current_id}")

        # Setting up regex and output file for this ID
        current_pattern = re.compile(re.escape(current_id), re.IGNORECASE)
        current_output_file = f"results_{id}.csv"

        # Searching through the PRs and split the dates when necessary
        all_pr_items = search_with_date_split(current_id, START_DATE_SEARCH, END_DATE_SEARCH)
        
        # See if there are any duplicates in the results
        seen_urls = set()
        unique_prs = []
        for item in all_pr_items:
            if item['html_url'] not in seen_urls:
                seen_urls.add(item['html_url'])
                unique_prs.append(item)

        if not unique_prs:
            print(f"No PRs found for {current_id}. Moving to next ID.")
            continue

        # The following is the more "advanced" analysis
        count = 0
        
        # Process each PR found
        for i, pr_stub in enumerate(unique_prs):
            try:
                repo_url_parts = pr_stub['repository_url'].split('/')
                owner = repo_url_parts[-2]
                name = repo_url_parts[-1]
                number = pr_stub['number']
                
                rows = analyze_single_pr_graphql(owner, name, number, current_id, current_pattern)
                
                if rows:
                    save_to_csv(rows, current_output_file)
                    count += len(rows)
                
                time.sleep(0.4) 
                
            except Exception as e:
                pass
        
        # Saving to checkpoint in case of GitHub limitations
        with open (f'checkpoint_other_mentions_{id}.txt', 'w') as file:
            file.write(str(current_id))

if __name__ == "__main__":
    # Parsing the users arguments 
    parser = argparse.ArgumentParser(description="Process a single ID")

    parser.add_argument(
        "id",
        choices=["cves", "cwes", "gos", "git_id"],
        help="ID to process"
    )

    parser.add_argument(
        "--author",
        default="agent",
        help="Author name"
    )

    args = parser.parse_args()

    main(id=args.id, author=args.author)