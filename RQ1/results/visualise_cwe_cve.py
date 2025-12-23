# %%
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("./source_column_breakdown.csv")
data = data.sort_values('total_cve_mentions', ascending=True)

data = data.loc[~(data[data.keys()[1:]] == 0).all(axis=1)]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

data.plot(
    kind='barh',
    x='source_column',
    y=['unique_cves', 'total_cve_mentions'],
    grid=True,
    ax=ax1,
    color=['#A890F0', "#FF6B6B"],
    width=0.8
)
ax1.set_title('CVE IDs per Source', fontsize=14, fontweight='bold')
ax1.set_xlabel('Number of Identifiers')
ax1.set_ylabel('Source')
ax1.grid(axis='x', linestyle='--', alpha=0.5)
ax1.legend(['Unique CVEs', 'Total Occurrences'])

for container in ax1.containers:
    ax1.bar_label(container, padding=3)

data.plot(
    kind='barh',
    x='source_column',
    y=['unique_cwes', 'total_cwe_mentions'],
    grid=True,
    ax=ax2,
    color=['#A890F0', "#FF6B6B"],
    width=0.8
)
ax2.set_title('CWE IDs Occurences per Source', fontsize=14, fontweight='bold')
ax2.set_xlabel('Number of Identifiers')
ax2.set_ylabel('Source')
ax2.grid(axis='x', linestyle='--', alpha=0.5)
ax2.legend(['Unique CWEs', 'Total Occurrences'], loc='lower right')

for container in ax2.containers:
    ax2.bar_label(container, padding=3)

plt.suptitle('Distribution of Unique Vulnerability Identifiers by Source', fontsize=16)
plt.tight_layout()
plt.savefig("images/cve_cwe_per_source.png")

#%%
import pandas as pd
import ast
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
plt.rcParams.update({'font.size': 14})

def parse_list_column(val):
    if pd.isna(val) or val == "":
        return []
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

def get_category_stats(df, col_name, top_n=10):
    exploded = df[[col_name, 'github_url']].explode(col_name)
    exploded = exploded.dropna(subset=[col_name])
    total_counts = exploded[col_name].value_counts()
    unique_counts = exploded.drop_duplicates(subset=[col_name, 'github_url'])[col_name].value_counts()
    
    combined = pd.DataFrame({
        'Affected PRs': unique_counts,
        'Total Mentions': total_counts
    }).fillna(0)

    return combined.sort_values('Total Mentions', ascending=False).head(top_n).sort_values('Total Mentions', ascending=True)

data = pd.read_csv("./cve_cwe_findings.csv")
list_cols = ['cves', 'cwes', 'gos', 'git_id']
for col in list_cols:
    data[col] = data[col].apply(parse_list_column)

df_cve = get_category_stats(data, 'cves', top_n=10)
df_ghsa = get_category_stats(data, 'git_id', top_n=10)
df_cwe = get_category_stats(data, 'cwes', top_n=10)
df_go = get_category_stats(data, 'gos', top_n=10) 

fig, axes = plt.subplots(2, 2, figsize=(16, 10))

def plot_category(ax, df, title, colors, y_label):
    df.plot(
        kind='barh', 
        ax=ax, 
        color=colors, 
        width=0.8
    )
    ax.set_title(title, fontweight='bold')
    ax.set_xlabel("Amount")
    ax.set_ylabel(y_label)
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles[::-1], labels[::-1], loc='lower right')

plot_category(axes[0, 0], df_cve, "Top 10 CVEs", ['#DCD0FF', '#7B61FF'], "CVE ID")
plot_category(axes[0, 1], df_ghsa, "Top 10 GHSAs", ['#FFB3B3', '#FF4D4D'], "GHSA ID")
plot_category(axes[1, 0], df_cwe, "Top 4 CWEs", ["#AEDD9E", "#60B543"], "CWE ID")
plot_category(axes[1, 1], df_go, "Top 7 GO IDs", ['#B2EBF2', '#00B8D4'], "GO ID")

fig.suptitle("Most Prevalent Vulnerability Identifiers: Total mentions vs. Affected PRs", fontsize=20, y=1.02, fontweight='bold')
plt.tight_layout()
plt.savefig("./images/total_vs_unique_comparison.png", bbox_inches='tight')
plt.show()

# %%
import pandas as pd
import ast
from collections import Counter

def parse_list(val):
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

def count_column_unique(csv_path, column):
    df = pd.read_csv(csv_path)

    values = []
    seen_urls = set()

    for _, row in df.iterrows():
        url = row['github_url']
        if url in seen_urls:
            continue

        lst = parse_list(row[column])
        values.extend(lst)
        seen_urls.add(url)

    return Counter(values)

def count_column(csv_path, column):
    df = pd.read_csv(csv_path)

    values = []
    for lst in df[column].dropna().map(parse_list):
        values.extend(lst)

    return Counter(values)

agent_url = "./cve_cwe_findings.csv"
human_url = "./human_pr_cve_cwe_findings.csv"
keys = ["gos", "git_id", "cves", "cwes"]

resulting = {}

for key in keys:
    resulting[key] = {
        "agent": {
            "counter": count_column(agent_url, key),
            "total": None,
        },
        "agent_unique": {
            "counter": count_column_unique(agent_url, key),
            "total": None,
        },
        "human": {
            "counter": count_column(human_url, key),
            "total": None,
        },
        "human_unique": {
            "counter": count_column_unique(human_url, key),
            "total": None,
        },
    }

for key in resulting:
    for kind in resulting[key]:
        c = resulting[key][kind]["counter"]
        resulting[key][kind]["total"] = sum(c.values())

# %%
import matplotlib.pyplot as plt
import numpy as np

def extract_totals(resulting):
    agent = []
    agent_unique = []
    human = []
    human_unique = []

    for _, group in resulting.items():
        agent.append(group["agent"]["total"])
        agent_unique.append(group["agent_unique"]["total"])
        human.append(group["human"]["total"])
        human_unique.append(group["human_unique"]["total"])

    return agent, agent_unique, human, human_unique

plot_keys = ['GO ID', 'GHSA ID', 'CVE ID', 'CWE ID']
agent, agent_unique, human, human_unique = extract_totals(resulting)
colors = ['#A890F0', '#4ECDC4', '#FF6B6B', '#2D3436']

x = np.arange(len(plot_keys))
width = 0.18  

fig, ax = plt.subplots(figsize=(9, 5))

ax.bar(x - 1.5*width, agent, width, label='Agent (Total Mentions)', color=colors[0])
ax.bar(x - 0.5*width, agent_unique, width, label='Agent (Unique IDs per PR)', hatch='///', edgecolor='white', color=colors[0])
ax.bar(x + 0.5*width, human, width, label='Human (Total Mentions)', color=colors[2])
ax.bar(x + 1.5*width, human_unique, width, label='Human (Unique IDs per PR)', hatch='///', edgecolor='white', color=colors[2])

ax.set_xticks(x)
ax.set_xticklabels(plot_keys)
ax.set_ylabel('Number of Identifiers')
ax.grid(linestyle='--', alpha=0.5)
ax.set_title('Distribution of Total and Unique Vulnerability Identifiers of PRs by Agent vs. Human')
ax.legend()

for container in ax.containers:
    ax.bar_label(container, padding=3)

plt.tight_layout()
plt.savefig("./images/overview_ids.png")
plt.show()

#%%
import pandas as pd
import ast
import matplotlib.pyplot as plt
import numpy as np
plt.rcParams.update({'font.size': 16})

df_human = pd.read_csv('human_pr_cve_cwe_findings.csv')
df = pd.read_csv('cve_cwe_findings.csv')

def parse_list(val):
    try:
        if isinstance(val, str) and val.strip():
            return ast.literal_eval(val)
        return []
    except (ValueError, SyntaxError, TypeError):
        return []

id_cols = ["gos", "git_id", "cves", "cwes"]
labels = ["GO ID", "GHSA ID", "CVE ID", "CWE ID"]
colors = ['#4ECDC4', '#FF6B6B', '#A890F0', '#60B543'] 

def make_grouped(df, type_label):
    df = df.copy()
    df['source_column'] = df['source'] + '.' + df['column']

    for col in id_cols:
        df[f'count_{col}'] = df[col].apply(lambda x: len(parse_list(x)))
    grouped = df.groupby('source_column')[[f'count_{col}' for col in id_cols]].sum()

    grouped.columns = labels
    grouped['Total'] = grouped.sum(axis=1)
    grouped['Type'] = type_label
    return grouped

# Prepare Data
grouped_agent = make_grouped(df, 'Agent')
grouped_human = make_grouped(df_human, 'Human')

# Rename Index
name_map = {
    "pull_request.body": "PR Body",
    "pull_request.title": "PR Title",
    "pr_comments.body": "PR Comments",
    "pr_reviews.body": "PR Reviews",
    "pr_commits.message": "Commit Msg",
    "issue.body": "Issue Body",
    "human_pull_request.body": "PR Body",
    "human_pull_request.title": "PR Title"
}
def rename_idx(df, prefix):
    new_index = [f"{prefix}: {name_map.get(i, i)}" for i in df.index]
    df.index = new_index
    return df

grouped_agent = rename_idx(grouped_agent, "Agent")
grouped_human = rename_idx(grouped_human, "Human")

combined = pd.concat([grouped_agent, grouped_human])
combined = combined.sort_values(by=['Type', 'Total'], ascending=[True, False])
n_agent = len(combined[combined['Type'] == 'Agent'])
separator_pos = n_agent - 0.5

combined_plot = combined.drop(columns=['Total', 'Type'])

fig, ax = plt.subplots(figsize=(15, 10)) 
combined_plot.plot(kind='barh', stacked=True, color=colors, ax=ax, width=0.8, fontsize=12)

for container in ax.containers:
    # Zip the bars with the dataframe index so we know which bar belongs to which row
    for patch, label in zip(container, combined_plot.index):
        if "Human" in label:
            patch.set_hatch('///')
            patch.set_edgecolor('white') # Optional: makes the hatch look cleaner against color
            patch.set_linewidth(0)

ax.invert_yaxis()

ax.set_title('Total Vulnerability Identifiers per Source', fontsize=20, pad=20, fontweight='bold')
ax.set_xlabel('Number of Identifiers', fontsize=16) # Swapped label
ax.set_ylabel('Source', fontsize=16)                # Swapped label
ax.grid(axis='x', linestyle='--', alpha=0.5)        # Grid on X axis now
ax.legend(title='Identifier Type', frameon=True, loc='upper right')

totals = combined['Total']
max_val = totals.max()
ax.set_xlim(0, max_val * 1.15) 

for i, (idx, total) in enumerate(totals.items()):
    ax.text(total + (max_val * 0.01), i, int(total), 
            ha='left', va='center', fontsize=12, fontweight='bold')

plt.tight_layout()
plt.savefig('./images/ids_per_source.png')
plt.show()

#%%
import pandas as pd
import ast
from collections import Counter
import matplotlib.pyplot as plt

def parse_list_column(val):
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

def process_url(url):
    parts = url.rstrip("/").split("/")
    return parts[4]

data = pd.read_csv("./cve_cwe_findings.csv")

repo_cve = set()
repo_cwe = set()
repo_gos = set()
repo_git = set()

for index, row in data.iterrows():
    if row['cves'] != '[]':
        cve_list = parse_list_column(row['cves'])
        for index, cve in enumerate(cve_list):
            repo_cve.add(process_url(row['github_url']))          
    if row['cwes'] != '[]':
        cwe_list = parse_list_column(row['cwes'])
        for index, cwe in enumerate(cwe_list):
            repo_cwe.add(process_url(row['github_url']))
    if row['gos'] != '[]':
        gos_list = parse_list_column(row['gos'])
        for index, go in enumerate(gos_list):
            repo_gos.add(process_url(row['github_url']))
    if row['git_id'] != '[]':
        git_list = parse_list_column(row['git_id'])
        for index, git in enumerate(git_list):
            repo_git.add(process_url(row['github_url']))
print(repo_cve, repo_cwe, repo_gos, repo_git)

# %%
import pandas as pd
import ast
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
plt.rcParams.update({'font.size': 16})

def parse_list_column(val):
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

def extract_repo_name(url):
    parts = url.rstrip("/").split("/")
    if len(parts) >= 5:
        return f"{parts[3]}/{parts[4]}"
    return "Unknown"

data = pd.read_csv("./cve_cwe_findings.csv")
repo_stats = defaultdict(lambda: {'CVE': 0, 'CWE':0, 'GHSA': 0, 'GO': 0})

for index, row in data.iterrows():
    repo_name = extract_repo_name(row['github_url'])
    
    if row['cves'] != '[]':
        findings = parse_list_column(row['cves'])
        repo_stats[repo_name]['CVE'] += len(findings)
    
    if row['cwes'] != '[]':
        findings = parse_list_column(row['cwes'])
        repo_stats[repo_name]['CWE'] += len(findings)
        
    if row['git_id'] != '[]':
        findings = parse_list_column(row['git_id'])
        repo_stats[repo_name]['GHSA'] += len(findings)
        
    if row['gos'] != '[]':
        findings = parse_list_column(row['gos'])
        repo_stats[repo_name]['GO'] += len(findings)

df_repos = pd.DataFrame.from_dict(repo_stats, orient='index')
df_repos = df_repos.fillna(0) 

df_repos['Total'] = df_repos['CVE'] + df_repos['CWE'] + df_repos['GHSA'] + df_repos['GO']

df_top_10 = df_repos.sort_values('Total', ascending=True)
df_plot = df_top_10[['CVE', 'CWE', 'GHSA', 'GO']]

fig, ax = plt.subplots(figsize=(12, 8))
colors = ['#A890F0', '#60B543', '#FF6B6B', '#4ECDC4']  

df_plot.plot(
    kind='barh', 
    stacked=True, 
    ax=ax, 
    color=colors,
    width=0.8,
    fontsize=12
)

for container in ax.containers:
    labels = [int(v) if v > 0 else '' for v in container.datavalues]
    
    ax.bar_label(
        container, 
        labels=labels, 
        label_type='center', 
        color='black',      
        fontsize=8
    )

ax.set_title("Vulnerability IDs per Repository", y=1.02, fontweight='bold')
ax.set_xlabel("Number of IDs")
ax.set_ylabel("Repository")
ax.legend(title="Vulnerability ID")
ax.grid(axis='x', linestyle='--', alpha=0.5)

ax.xaxis.set_major_locator(MaxNLocator(integer=True))

plt.tight_layout()
plt.savefig("./images/repo.png")
plt.show()

# %%
import pandas as pd
import ast
from collections import Counter
import json

df = pd.read_csv("cve_cwe_findings.csv")
df_human = pd.read_csv("human_pr_cve_cwe_findings.csv")

def parse_list_column(val):
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

result_dict = {}
id_keys = ['cves', 'cwes', 'gos', 'git_id']
for key in id_keys: 
    uniques = []
    uniques_human = []
    for index, row in df.iterrows(): 
        if row[key] != '[]':
            inter_list = parse_list_column(row[key])
            for cve in inter_list:
                uniques.append(cve)
    for index, row in df_human.iterrows():
        if row[key] != '[]':
            inter_list = parse_list_column(row[key])
            for id in inter_list:
                uniques_human.append(id)
    unique_counter = Counter(uniques)
    unique_counter_human = Counter(uniques_human)
    result_dict[key] = {
        "agent": list(unique_counter.keys()),
        "human": list(unique_counter_human.keys())
    }

with open("all_ids.json", "w") as f: 
    json.dump(result_dict, f, indent=4)

# %%

import pandas as pd
import ast
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
plt.rcParams.update({'font.size': 14})

def parse_list_column(val):
    if pd.isna(val) or val == "":
        return []
    try:
        return ast.literal_eval(val)
    except (ValueError, SyntaxError):
        return []

def get_category_stats(df, col_name, top_n=10):
    exploded = df[[col_name, 'github_url']].explode(col_name)
    exploded = exploded.dropna(subset=[col_name])
    total_counts = exploded[col_name].value_counts()
    unique_counts = exploded.drop_duplicates(subset=[col_name, 'github_url'])[col_name].value_counts()
    
    combined = pd.DataFrame({
        'Affected PRs': unique_counts,
        'Total Mentions': total_counts
    }).fillna(0)

    return combined.sort_values('Total Mentions', ascending=False).sort_values('Total Mentions', ascending=True)

data = pd.read_csv("./cve_cwe_findings.csv")
list_cols = ['cves', 'cwes', 'gos', 'git_id']
for col in list_cols:
    data[col] = data[col].apply(parse_list_column)

df_cve = get_category_stats(data, 'cves', top_n=10)
df_ghsa = get_category_stats(data, 'git_id', top_n=10)
df_cwe = get_category_stats(data, 'cwes', top_n=10)
df_go = get_category_stats(data, 'gos', top_n=10) 

def print_statistics(df):
    print(f"Max:{df['Total Mentions'].max()}")
    print(f"Mean:{round(df['Total Mentions'].mean())}")
    print(f"Median:{df['Total Mentions'].median()}")
    print("-"*60)
    print("PRS:")
    print(f"Max:{df['Affected PRs'].max()}")
    print(f"Mean:{round(df['Affected PRs'].mean())}")
    print(f"Median:{df['Affected PRs'].median()}")
    print("-"*60)

print_statistics(df_cve)
print_statistics(df_cwe)
print_statistics(df_ghsa)
print_statistics(df_go)
# %%
