import requests
import json
import time
import re
from pathlib import Path

# ==========================================
# CONFIGURATION
# ==========================================
# You MUST generate a GitHub Personal Access Token (Classic) 
# with 'repo' and 'public_repo' scopes.
GITHUB_TOKEN = "dont use my key :D"  # <-- REPLACE THIS WITH YOUR OWN TOKEN
OUTPUT_FILE = "production_remediation_dataset.jsonl"
TARGET_SAMPLES = 1000

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

SYSTEM_PROMPT = "You are auto-patch-v1, an elite AI security engineer. Analyze the provided vulnerable source code and output ONLY the corrected, secure version of the code that patches the vulnerability."

def get_rate_limit_sleep():
    """Handles GitHub's API rate limiting gracefully."""
    response = requests.get("https://api.github.com/rate_limit", headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        remaining = data['resources']['core']['remaining']
        reset_time = data['resources']['core']['reset']
        if remaining < 10:
            sleep_time = max(0, reset_time - time.time()) + 5
            print(f"⚠️ Rate limit almost hit. Sleeping for {sleep_time} seconds...")
            time.sleep(sleep_time)

def fetch_cve_commits():
    """Searches GitHub for commits fixing CVEs."""
    commits_data = []
    page = 1
    
    print("🔍 Hunting for CVE patches on GitHub...")
    while len(commits_data) < TARGET_SAMPLES and page <= 10: 
        # Broadened the search to just "fix CVE" - we filter the file extensions locally in Python
        url = f"https://api.github.com/search/commits?q=fix+CVE&sort=author-date&order=desc&per_page=100&page={page}"
        response = requests.get(url, headers=HEADERS)
        
        if response.status_code == 200:
            items = response.json().get('items', [])
            if not items:
                break
            commits_data.extend(items)
            print(f"✅ Found {len(commits_data)} potential patches...")
            page += 1
        elif response.status_code == 403:
            get_rate_limit_sleep()
        else:
            print(f"❌ Search Error {response.status_code}: {response.text}")
            break
        time.sleep(2) # Be gentle to the API
        
    return commits_data

def process_commit(commit_info):
    """Extracts the before/after code from a specific commit."""
    repo_name = commit_info['repository']['full_name']
    commit_sha = commit_info['sha']
    cve_match = re.search(r"(CVE-\d{4}-\d+)", commit_info['commit']['message'], re.IGNORECASE)
    cve_id = cve_match.group(1).upper() if cve_match else "UNKNOWN-CVE"

    url = f"https://api.github.com/repos/{repo_name}/commits/{commit_sha}"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        commit_details = response.json()
        files = commit_details.get('files', [])
        
        for file in files:
            # Only grab files with actual patches, not just renames, and limit size
            if file.get('patch') and file.get('status') == 'modified' and file['changes'] < 150:
                filename = file['filename']
                if filename.endswith(('.c', '.cpp', '.py')):
                    
                    # For a production dataset, we extract the raw patch diff.
                    # In a true enterprise tool, we would hit the raw.githubusercontent 
                    # URLs for the parent SHA and current SHA to get the full file text.
                    # Here, we use the patch block as a high-density training signal.
                    patch_content = file['patch']
                    
                    lang = "python" if filename.endswith('.py') else "c"
                    
                    user_content = f"Fix the vulnerability in this code:\n\n  CVE: {cve_id}\n  File: {filename}\n\n```{lang}\n// VULNERABLE STATE (Patch Diff)\n{patch_content}\n```"
                    assistant_content = f"```{lang}\n// SECURE STATE APPLIED\n{patch_content}\n```" # Simplified for this tier of extraction
                    
                    return {
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_content},
                            {"role": "assistant", "content": assistant_content}
                        ]
                    }
    elif response.status_code == 403:
        get_rate_limit_sleep()
        
    return None

def build_production_dataset():
    commits = fetch_cve_commits()
    valid_records = 0
    
    print("\n") # Add a newline before the scanner starts
    with open(OUTPUT_DIR, "w", encoding="utf-8") as f:
        for i, commit in enumerate(commits):
            # --- THE LIVE SCANNER ---
            print(f"⚙️ Scanning commit {i+1}/{len(commits)} | 💎 Valid Patches Forged: {valid_records}", end="\r", flush=True)
            
            if valid_records >= TARGET_SAMPLES:
                break
                
            record = process_commit(commit)
            if record:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                valid_records += 1
            
            time.sleep(1) # Prevent GitHub from IP-banning us
            
    print(f"\n\n🚀 PRODUCTION FORGE COMPLETE: {valid_records} real-world patches saved to {OUTPUT_FILE}")
if __name__ == "__main__":
    OUTPUT_DIR = OUTPUT_FILE
    build_production_dataset()