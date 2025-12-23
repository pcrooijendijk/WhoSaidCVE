#%%
import os
import nvdlib
from dotenv import load_dotenv
import xml.etree.ElementTree as ET

load_dotenv()  

NVD_KEY = os.getenv("NVD_KEY")

# Getting the CWE information from the NVD based on the CVE IDs
cwe_ids = []
with open("all_cves.txt", "r") as f: 
    for line in f:
        print(line)
        cve_id = line.strip()

        r = nvdlib.searchCVE(
            cveId=cve_id,
            key=NVD_KEY
        )[0]

        all_cve_ids = []
        try:
            for i in r.weaknesses:
                for j in i.description:
                    all_cve_ids.append(j.value)
        except AttributeError: # These CVE IDs do not have a CWE ID 
            print(cve_id)
        print(all_cve_ids)
        cwe_ids.append(all_cve_ids)

#%%
tree = ET.parse("cwec_v4.19.xml")
root = tree.getroot()

ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

cwe_lookup = {}

# Getting information from the CWE database 
for weakness in root.findall(".//cwe:Weakness", ns):
    cwe_id = f"CWE-{weakness.attrib['ID']}"
    cwe_name = weakness.attrib["Name"]
    cwe_lookup[cwe_id] = cwe_name

descriptions = []
for cwe in cwe_ids:
    for id in cwe:
        print(id)
        if id != "NVD-CWE-noinfo": # Some of the CVE IDs did not have a CWE ID/information
            descriptions.append(cwe_lookup[id])

print(descriptions)

#%%
tree = ET.parse("cwec_v4.19.xml")
root = tree.getroot()
ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

def get_all_members(element, collected=None):
    if collected is None:
        collected = set()

    for tag in ["./cwe:Members/cwe:Has_Member", "./cwe:Relationships/cwe:Has_Member"]:
        for member in element.findall(tag, ns):
            member_id = member.attrib['CWE_ID']
            if member_id not in collected:
                collected.add(member_id)
                category = root.find(f".//cwe:Category[@ID='{member_id}']", ns)
                if category is not None:
                    get_all_members(category, collected)
    return collected

view_699 = root.find(".//cwe:View[@ID='699']", ns)
software_dev_ids = set()
view_name = "Unknown"

if view_699 is not None:
    view_name = view_699.attrib.get('Name', "Unknown")
    software_dev_ids = get_all_members(view_699)
    print(f"\nFound {len(software_dev_ids)} weaknesses inside '{view_name}'\n")

category_cache = {}

def members_cached(cat_node):
    cid = cat_node.attrib['ID']
    if cid not in category_cache:
        category_cache[cid] = get_all_members(cat_node)
    return category_cache[cid]

for cwe_list in cwe_ids:
    for cwe_id in cwe_list:
        cwe_id = cwe_id.strip("CWE-")
        print(f"Checking CWE-{cwe_id}...")

        if cwe_id in software_dev_ids:
            for cat_member in view_699.findall("./cwe:Members/cwe:Has_Member", ns):
                cat_id = cat_member.attrib['CWE_ID']
                cat_node = root.find(f".//cwe:Category[@ID='{cat_id}']", ns)
                if cat_node and cwe_id in members_cached(cat_node):
                    print(f"   -> Specifically part of Category: {cat_node.attrib['Name']} (CWE-{cat_id})")
        else:
            print(f"   -> Not in Software Development view")


# %%
from collections import Counter
from more_itertools import flatten

cwe_ids_flatten = list(flatten(cwe_ids))
counter = Counter(cwe_ids_flatten)

overview = []
print(counter)
for cwe_id, count in counter.items():
    name = cwe_lookup.get(cwe_id, "")
    print(name)
    if name:
        overview.append({
            "cwe_id": cwe_id,
            "name": name,
            "occurrences": count
        })

# %%
overview.sort(key=lambda x: x["occurrences"], reverse=True)
print("CWE-ID & Count & CWE name")
print("\hline")

for row in overview:
    print(
        f"{row['cwe_id']:<12} &"
        f"{row['occurrences']:<6} &"
        f"{row['name']} \\\\"
    )

# %%
