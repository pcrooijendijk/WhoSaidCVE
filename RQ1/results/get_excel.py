import pandas as pd
import os
import tempfile
import requests
import re
from random import sample

data = pd.read_csv('./cve_cwe_findings.csv')

SECURITY_KEYWORDS = [
    'vulnerability', 'vulnerabilities', 'vulnerable',  # Any variant of vulnerability
    'security',
    #  'bump', 'bumps', # Use this?
    'security fix', 'security patch', 'security update',
    'critical', 'high severity', 'medium severity', # Levels of severity of vulnerabilities
    'fix security vulnerabilities', 'security: fix', # Other templates some bots use
]

# Printing the different CWE and CVE counts
data['source_column'] = data['source'] + '.' + data['column']
source_column_counts = data['source_column'].value_counts()
print(data['source_column'])
for source_col, count in source_column_counts.items():
    print(f"  {source_col}: {count}")
print(data['source'].value_counts())

def get_html_url(url_link, token=None):
    # Check if the URL link is an API link, if so then get the HTML URL form this API link
    if "api" in url_link:
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        try:
            response = requests.get(url_link, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            return None

        data = response.json()
        return data['html_url']
    else: # Return the original link is it is not an API link
        return url_link
    
def sample_per_keyword():
    df_excel = []
    text = " ".join(data['keywords'].astype(str))

    counts = {}
    for kw in SECURITY_KEYWORDS:
        counts[kw] = len(re.findall(rf'\b{re.escape(kw)}\b', text, flags=re.IGNORECASE))
    keywords = list(counts.keys())
    # values = list(counts.values())

    for keyword in keywords:
        # data_subset = data[keyword in data['keywords']]
        # data_subset = list(filter(lambda lst: keyword in lst, data['keywords']))
        data_subset = data[data['keywords'].apply(lambda lst: keyword in lst)]
        # data_subset = data[data['keywords'].filter(lambda lst: isinstance(lst, list) and keyword in lst)]

        # Take all samples if the total number of CVE or CWE IDs mentioned in this subset is less than 10
        if len(data_subset) < 10:
            inter = []
            for index, row in data_subset.iterrows():
                html_url = get_html_url(row['github_url'])
                if html_url:
                    result = {
                        "CVE ID": row['cves'].strip("[").strip("]").replace("'", ""),
                        "CWE ID": row['cwes'].strip("[").strip("]").replace("'", ""),
                        "keyword": keyword,
                        "URL": html_url,
                    }
                    inter.append(result)
            df_excel.extend(inter)
        else: # Sample 10 random samples from the subsets for evaluation
            inter = []
            random_subset = data_subset.sample(
                n=5, 
                random_state=42,
            )

            for index, row in random_subset.iterrows():
                html_url = get_html_url(row['github_url'])
                if html_url:
                    result = {
                        "CVE ID": row['cves'].strip("[").strip("]").replace("'", ""),
                        "CWE ID": row['cwes'].strip("[").strip("]").replace("'", ""),
                        "keyword": keyword,
                        "URL": html_url,
                    }
                inter.append(result)
            df_excel.extend(inter)

    # Saving the dataset to a dataframe and then save it to an Excel sheet
    df = pd.DataFrame(df_excel)
    return df

def sample_per_source():
    # Sample 10 random rows from each source so also random sampling of CWE and CVE IDs
    df_excel = []
    source_names = set(data['source_column'])
    for name in source_names:
        data_subset = data[data['source_column']==name]

        # Take all samples if the total number of CVE or CWE IDs mentioned in this subset is less than 10
        if len(data_subset) < 10:
            inter = []
            for index, row in data_subset.iterrows():
                html_url = get_html_url(row['github_url'])
                if html_url:
                    result = {
                        "CVE ID": row['cves'].strip("[").strip("]").replace("'", ""),
                        "CWE ID": row['cwes'].strip("[").strip("]").replace("'", ""),
                        "source": name,
                        "URL": html_url,
                    }
                    inter.append(result)
            df_excel.extend(inter)
        else: # Sample 10 random samples from the subsets for evaluation
            inter = []
            random_subset = data_subset.sample(
                n=10, 
                random_state=42,
            )

            for index, row in random_subset.iterrows():
                html_url = get_html_url(row['github_url'])
                if html_url:
                    result = {
                        "CVE ID": row['cves'].strip("[").strip("]").replace("'", ""),
                        "CWE ID": row['cwes'].strip("[").strip("]").replace("'", ""),
                        "source": name,
                        "URL": html_url,
                    }
                inter.append(result)
            df_excel.extend(inter)

    # Saving the dataset to a dataframe and then save it to an Excel sheet
    df = pd.DataFrame(df_excel)
    return df

def get_other_ids():
    # Sample 10 random rows from each source so also random sampling of other IDs
    df_excel = []
    for _, row in data.iterrows():
        if row['gos'] != '[]':
            print(row['gos'])
            inter = []
            html_url = get_html_url(row['github_url'])
            if html_url:
                result = {
                    "GO ID": row['gos'].strip("[").strip("]").replace("'", ""),
                    "GHSA ID": row['git_id'].strip("[").strip("]").replace("'", ""),
                    "source": f"{row['source']}.{row['column']}",
                    "URL": html_url,
                }
                inter.append(result)
            df_excel.extend(inter)
        if row['git_id'] != '[]':
            inter = []
            html_url = get_html_url(row['github_url'])
            if html_url:
                result = {
                    "GO ID": row['gos'].strip("[").strip("]").replace("'", ""),
                    "GHSA ID": row['git_id'].strip("[").strip("]").replace("'", ""),
                    "source": f"{row['source']}.{row['column']}",
                    "URL": html_url,
                }
                inter.append(result)
            df_excel.extend(inter)

    # Saving the dataset to a dataframe and then save it to an Excel sheet
    df = pd.DataFrame(df_excel)
    return df

def safe_to_excel(df, final_path):
    temp_dir = os.path.dirname(final_path)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx", dir=temp_dir) as tmp:
        temp_path = tmp.name

    df.to_excel(
        temp_path,
        index=False,
        engine="openpyxl"
    )

    os.replace(temp_path, final_path) 

def sample_all_sources():
    data = pd.read_csv('./human_pr_cve_cwe_findings.csv')
    data['source_column'] = data['source'] + '.' + data['column']
    # Sample 10 random rows from each source so also random sampling of CWE and CVE IDs
    df_excel = []
    source_names = set(data['source_column'])
    for name in source_names:
        data_subset = data[data['source_column']==name]
        inter = []
        for index, row in data_subset.iterrows():
            html_url = get_html_url(row['github_url'])
            if html_url:
                result = {
                    "GO ID": row['gos'].strip("[").strip("]").replace("'", ""),
                    "GHSA ID": row['git_id'].strip("[").strip("]").replace("'", ""),
                    "CVE ID": row['cves'].strip("[").strip("]").replace("'", ""),
                    "CWE ID": row['cwes'].strip("[").strip("]").replace("'", ""),
                    "source": name,
                    "URL": html_url,
                }
                inter.append(result)
        df_excel.extend(inter)

    # Saving the dataset to a dataframe and then save it to an Excel sheet
    df = pd.DataFrame(df_excel)
    return df
    
# df = sample_per_source()
# safe_to_excel(df, "report.xlsx")

# df = sample_per_keyword()
# safe_to_excel(df, "keywords.xlsx")

# df = get_other_ids()
# print(df)
# safe_to_excel(df, "report_other_ids.xlsx")

df = sample_all_sources()
safe_to_excel(df, "report_all_ids_human.xlsx")