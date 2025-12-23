import pandas as pd
import re
from collections import defaultdict
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from github import Github, Auth
import os

load_dotenv() 
KEYS = [os.getenv(f"KEY_{i}") for i in range(11)]
KEY_INDEX = 1 # For keeping track of the GitHub key in use

# Loading the datasets
pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pull_request.parquet")
repo_df = pd.read_parquet("hf://datasets/hao-li/AIDev/repository.parquet")
user_df = pd.read_parquet("hf://datasets/hao-li/AIDev/user.parquet")
pr_comments_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_comments.parquet")
pr_reviews_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_reviews.parquet")
pr_review_comments_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_review_comments_v2.parquet")
pr_commits_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_commits.parquet")
pr_commit_details_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_commit_details.parquet")
related_issue_df = pd.read_parquet("hf://datasets/hao-li/AIDev/related_issue.parquet")
issue_df = pd.read_parquet("hf://datasets/hao-li/AIDev/issue.parquet")
pr_timeline_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_timeline.parquet")
pr_task_type_df = pd.read_parquet("hf://datasets/hao-li/AIDev/pr_task_type.parquet")
human_pr_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pull_request.parquet")
human_pr_task_type_df = pd.read_parquet("hf://datasets/hao-li/AIDev/human_pr_task_type.parquet")

# Regex patterns for every different vulnerability identification according to https://ossf.github.io/osv-schema/
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

# Using regex to extract the IDs from text
def search_ids(text):
    if pd.isna(text) or not isinstance(text, str):
        return {}

    results = {}

    for name, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results[name] = sorted(set(m.upper() for m in matches))

    return results

def change_key(g: Github) -> Github:
    # Function for changing the key to the next one
    global KEY_INDEX
    KEY_INDEX = (KEY_INDEX + 1) % len(KEYS) # Ensures going back to the first key if needed
    auth = Auth.Token(KEYS[KEY_INDEX])
    g = Github(auth=auth)
    return g

# Searching through a specified column in the data
def search_data(df, text_columns, df_name):
    results = []
    
    for col in text_columns:
        if col not in df.columns:
            continue
        
        for idx, row in df.iterrows():
            text = row.get(col)
            matches = search_ids(text)
            print(matches)
            
            if matches:
                # Only adding results if an ID was found
                result = {
                    'source': df_name,
                    'column': col,
                    'index': idx,
                    'vulnerability': matches,
                    'text_snippet': str(text), # Adding the text where the ID was found
                }
                
                # Adding the rows to the resulting list
                id = None
                # First get the pr id, in some of the subset datasets, the names for pr id are different
                if 'id' in row:
                    result['id'] = int(row['id'])
                    id = int(row['id'])
                if 'pr_id' in row:
                    result['pr_id'] = int(row['pr_id'])
                    id = int(result['pr_id'])
                if 'repo_id' in row:
                    result['repo_id'] = int(row['repo_id'])
                if "pr_review_comments" in df_name:
                    result['github_url'] = row['pull_request_url']

                # Getting the HTML URL for every entry in the resulting dataset
                elif 'html_url' not in row:
                    html_url : str = pr_df[pr_df['id']==id]['html_url'].item()
                    if "nuclei-templates" in html_url: # Exclude the outlier in the dataset: repository filled with CVE templates
                        continue
                    if "pr_commit_details" in df_name: # Add the correct reference to the commit message 
                        parsed = urlparse(html_url)
                        parts = parsed.path.strip("/").split("/")
                        sha = row['sha']
                        owner, repo = parts[0], parts[1]
                        result['github_url'] = f"https://github.com/{owner}/{repo}/commit/{sha}"
                    else:
                        result['github_url'] = html_url
                else: 
                    result['github_url'] = row['html_url']

                # Getting the label for every pull request
                if 'pr_review_comments' in df_name:
                    id = row['pull_request_review_id']
                results.append(result)
    
    return results

# Columns used for CWE or CVE key word search
key_words = {
    'pull_request': ['title', 'body'],
    'pr_comments': ['body'],
    'pr_reviews': ['body'],
    'pr_review_comments': ['body'],
    'pr_commits': ['message'],
    'issue': ['title', 'body'],
    'pr_timeline': ['message'],
}

datasets = {
    'pull_request': pr_df,
    'pr_comments': pr_comments_df,
    'pr_reviews': pr_reviews_df,
    'pr_review_comments': pr_review_comments_df,
    'pr_commits': pr_commits_df,
    'pr_commit_details': pr_commit_details_df,
    'issue': issue_df,
    'pr_timeline': pr_timeline_df,
}

# For saving the results
all_results = []

# Going through the different datasets from Huggingface and search for the columns to search for CWE or CVE IDs
for df_name, df in datasets.items():
    if df_name in key_words:
        results = search_data(df, key_words[df_name], df_name)
        all_results.extend(results)

# Convert to DataFrame and save the CSV file
results_df = pd.DataFrame(all_results)

# Removing the CVE/CWE template repo
repo_name = "nuclei-templates" 
mask = results_df['github_url'].str.contains(repo_name, na=False)
repo_id_to_remove = results_df.loc[mask, 'id'].values[0]
results_df = results_df[~mask]
results_df.to_csv('vulnerability_findings.csv', index=False)

# For counting all unique CVEs and CWEs
all_cves = []
all_cwes = []

for _, row in results_df.iterrows():
    all_cves.extend(row['cves'])
    all_cwes.extend(row['cwes'])

unique_cves = sorted(set(all_cves))
unique_cwes = sorted(set(all_cwes))

# Basic stats
print(f"\nTotal matches found: {len(results_df)}")
print(f"Unique CVEs found: {len(unique_cves)}")
print(f"Unique CWEs found: {len(unique_cwes)}")

# ---------------------------- More detailed analysis ----------------------------

# ---------------------------- Analyzing the CVE/CWE per sources ----------------------------
print("Total count of CVE or CWE across different sources:\n")
results_df['source_column'] = results_df['source'] + '.' + results_df['column']

source_column_counts = results_df['source_column'].value_counts()
for source_col, count in source_column_counts.items():
    print(f"  {source_col}: {count}")
print("-"*80)
print(results_df['source_column'].value_counts())

# Analysis by individual CVE and CWE per source
cve_by_source = defaultdict(lambda: defaultdict(int))
cwe_by_source = defaultdict(lambda: defaultdict(int))

# Track URLs for each CVE/CWE
cve_urls = defaultdict(set)
cwe_urls = defaultdict(set)

# Counting the CVE/CWE IDs
for _, row in results_df.iterrows():
    source_col = row['source_column']
    github_url = row.get('github_url', '')
    
    for cve in row['cves']:
        cve_by_source[cve][source_col] += 1
        if github_url:
            cve_urls[cve].add(github_url)
    
    for cwe in row['cwes']:
        cwe_by_source[cwe][source_col] += 1
        if github_url:
            cwe_urls[cwe].add(github_url)

# Make CSV with the different sources in there and unique IDs and total CWE/CVE metions
source_breakdown = []
for source_col in results_df['source_column'].unique():
    subset = results_df[results_df['source_column'] == source_col]
    
    cves_in_source = []
    cwes_in_source = []
    for _, row in subset.iterrows():
        cves_in_source.extend(row['cves'])
        cwes_in_source.extend(row['cwes'])
    
    source_breakdown.append({
        'source_column': source_col,
        'unique_cves': len(set(cves_in_source)),
        'unique_cwes': len(set(cwes_in_source)),
        'total_cve_mentions': len(cves_in_source),
        'total_cwe_mentions': len(cwes_in_source)
    })

# Saving the CSV file
source_breakdown_df = pd.DataFrame(source_breakdown)
source_breakdown_df = source_breakdown_df.sort_values('total_cve_mentions', ascending=False)
source_breakdown_df.to_csv('source_column_breakdown.csv', index=False)