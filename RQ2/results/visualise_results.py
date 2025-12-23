#%%
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

colors = ['#4ECDC4', '#FF6B6B', '#A890F0', '#60B543']

df_cwe = pd.read_csv("results_cwes.csv")
df_cve = pd.read_csv("results_cves.csv")
df_go = pd.read_csv("results_gos_final.csv")
df_git = pd.read_csv("results_git_id.csv")

datasets = [
    ('CWE ID', df_cwe),
    ('CVE ID', df_cve),
    ('GO ID', df_go),
    ('GHSA ID', df_git)
]

MENTIONER_ORDER = [
    "Bot",
    "Human",
    "Agent"
]

SOURCE_ORDER = [
    "PR Body",
    "PR Title",
    "Commit Message",
    "Review Summary",
    "Inline Code Comment",
    "Inlince Review Comment"
]

def plot_countplot(df, col, ax, title, palette, label_fix=None, order=None):
    if df.empty:
        ax.text(0.5, 0.5, 'No Data', ha='center', va='center', fontsize=25)
        ax.set_title(title, fontsize=28)
        ax.set_xticks([])
        ax.set_yticks([])
        return
    
    sns.countplot(data=df, y=col, palette=sns.color_palette(palette, 8)[2:], ax=ax, order=order)
    ax.set_title(title, fontsize=28, fontweight='bold')
    ax.set_xlabel('Amount of Mentions', fontsize=24)
    if label_fix:
        ax.set_ylabel(label_fix, fontsize=24)
    else:
        ax.set_ylabel(col, fontsize=24)
    ax.tick_params(axis='both', which='major', labelsize=22)
    
    for container in ax.containers:
        ax.bar_label(container, label_type='edge', padding=5, fontsize=20)
    
    max_count = df[col].value_counts().max()
    if not np.isnan(max_count):
        ax.set_xlim(0, max_count * 1.25)

fig, axes = plt.subplots(4, 2, figsize=(30, 30))
fig.suptitle('Vulnerability Mentions by User and Source', fontsize=36, y=1.02, fontweight='bold')

for i, (name, df) in enumerate(datasets):
    df_filtered = df[(df['Mentioner_Type'] != 'Unknown') & (df['Source'] != 'review_summary') & (df['Source'] != 'Code/Diff (Search Match)')]
    row = i
    plot_countplot(df_filtered, 'Mentioner_Type', axes[row, 0], f'{name}: User Type', palette='viridis', label_fix='User', order=MENTIONER_ORDER)
    plot_countplot(df_filtered, 'Source', axes[row, 1], f'{name}: Source', palette='magma', order=SOURCE_ORDER)

plt.tight_layout()
plt.savefig("./images/additional_prs.png")
plt.show()

# %%
import pandas as pd

df_cwe = pd.read_csv("results_cwes.csv")
df_cve = pd.read_csv("results_cves.csv")
df_go = pd.read_csv("results_gos_final.csv")
df_git = pd.read_csv("results_git_id.csv")

df = pd.concat([df_cwe, df_cve, df_go, df_git], ignore_index=True)

stats = df['Total_Comments'].describe()
print(stats)
print(df.groupby('PR_State')['Total_Comments'].describe())
print(df.groupby('Mentioner_Type')['Total_Comments'].describe())

# %%
import pandas as pd

df_cwe = pd.read_csv("results_cwes.csv")
df_cve = pd.read_csv("results_cves.csv")
df_go = pd.read_csv("results_gos_final.csv")
df_git = pd.read_csv("results_git_id.csv")

df = pd.concat([df_cwe, df_cve, df_go, df_git], ignore_index=True)
print(df['Other_Bots'].value_counts())
print(len(list(df['Other_Bots'].unique())))
# %%
