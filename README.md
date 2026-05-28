Rancher CVE AppCo Analyzer (Enterprise Hybrid Edition)
A robust, enterprise-grade Vulnerability Management tool designed to bridge the gap between Rancher CVE scan reports and the SUSE Application Collection (AppCo).

This tool automatically analyzes Rancher cluster CVE reports, matches them against the AppCo API, and generates actionable upgrade recommendations—telling you exactly which vulnerabilities can be mitigated by switching to SUSE's hardened images.

✨ Key Features
Full Context Retention: Keeps all original CVE report columns (justification, patched_version, status, etc.) intact.

Smart Upgrade Awareness: Distinguishes between Exact Match (swap URLs directly), Upgrade Available (requires version bump), and Not Found.

Dynamic Prefix Stripping: Automatically strips overlapping Rancher metadata prefixes (appco-, mirrored-, hardened-, rancher-).

Human-in-the-Loop Aliasing: Supports a strict aliases.json dictionary for absolute control over quirky upstream naming.

Ollama AI Fallback: Integrates with local Small Language Models (SLMs) like llama3 to dynamically infer clean upstream project names when standard rules fail (Zero-maintenance scaling).

🚀 Installation
1. Clone the repository & install dependencies
git clone [YOUR_REPO_URL]
cd rancher_sec_analyzer
python3 -m venv venv
source venv/bin/activate
pip install requests urllib3 beautifulsoup4 python-dotenv tqdm

2. Configure Environment Variables
Create a .env file in the root directory. Note: This file is ignored by Git to protect your secrets.

SUSE_APPCO_USER=your_service_account

SUSE_APPCO_SECRET=your_secret_token

#Filtering Options
#INCLUDE_HEAD_RELEASES=false

Setup AI Fallback (Optional, requires Ollama running locally)

USE_OLLAMA_AI=true

OLLAMA_MODEL=llama3

3. Define Custom Aliases (Optional, already have default mappings)
Create an aliases.json in the root directory to handle hardcoded naming exceptions. The script processes these after stripping system prefixes.

{
"grafana-grafana-image-renderer": "grafana-image-renderer",
"prom-prometheus": "prometheus",
"longhornio-backing-image-manager": "longhorn-backing-image-manager"
}

🛠️ Usage
Run the script to analyze all available stable releases:
python rancher_sec_analyzer.py

Filter by a specific Rancher version:
python rancher_sec_analyzer.py -v rancher-v2.14.1

Force enable AI fallback via CLI (overrides .env):
python rancher_sec_analyzer.py -v rancher-v2.14.1 --use-ai --ai-model qwen2.5

📊 Output Files
rancher_mapping_full.csv: The complete mapping report with all original context and newly appended AppCo statuses.

rancher_summary.csv: A high-level executive summary of remaining vulnerabilities (grouped by Image -> Version -> Severity).

📄 License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

Authors: Sam Chen & Gemini (2026)
