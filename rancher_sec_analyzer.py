# -*- coding: utf-8 -*-
"""
Rancher CVE AppCo Analyzer (Enterprise Hybrid Edition)
Author: Gemini
Date: 2026-05-28
Description: 
    - 3-tier hybrid architecture: JSON Whitelist -> Prefix Filtering -> Ollama AI Inference.
    - Excludes 'not_affected' statuses automatically.
    - Fully translated into English for CI/CD compatibility.
"""

import os
import re
import csv
import json
import logging
import argparse
from collections import defaultdict
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from tqdm import tqdm

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class OllamaClient:
    def __init__(self, model_name=None):
        self.base_url = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model_name or os.getenv("OLLAMA_MODEL", "llama3")
        self.session = requests.Session()
        
    def infer_true_name(self, raw_image_name):
        prompt = f"""
        You are an expert in Kubernetes and Docker image naming conventions.
        I will give you a messy container image name (often mirrored by Rancher) and you need to output ONLY the clean upstream open-source project name (the Component Slug).
        
        Rules:
        1. Remove organizational prefixes if they are repeated (e.g., 'grafana-grafana-image-renderer' -> 'grafana-image-renderer').
        2. Remove generic grouping prefixes if they hide the core app (e.g., 'prom-prometheus' -> 'prometheus').
        3. Do NOT output any explanation, markdown, or chat. Output ONLY the raw slug.
        
        Input: {raw_image_name}
        Output:
        """
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0}
        }
        
        try:
            res = self.session.post(f"{self.base_url}/api/generate", json=payload, timeout=10)
            if res.status_code == 200:
                response_text = res.json().get("response", "").strip()
                clean_name = re.sub(r'[^a-zA-Z0-9-]', '', response_text)
                return clean_name
        except requests.exceptions.RequestException as e:
            logging.debug(f"Ollama connection failed or timed out: {e}")
            return None
        return None


class APIClient:
    def __init__(self, ollama_client=None):
        self.username = os.getenv("SUSE_APPCO_USER", "")
        self.password = os.getenv("SUSE_APPCO_SECRET", "")
        self.api_url = os.getenv("SUSE_APPCO_API_URL", "https://api.apps.rancher.io/v1/artifacts")
        self.session = self._create_session()
        self.cache = {}
        self.ollama = ollama_client

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if self.username and self.password:
            session.auth = (self.username, self.password)
        return session

    def check_appco_image(self, search_name, tag, is_fallback=False, original_raw_name=None):
        cache_key = f"{search_name}:{tag}"
        if cache_key in self.cache: 
            return self.cache[cache_key]
            
        params = {"component_slug_name": search_name, "packaging_formats": "CONTAINER"}
        try:
            res = self.session.get(self.api_url, params=params, timeout=10)
            if res.status_code == 200 and res.json().get("items"):
                items = res.json().get("items")
                versions_set = {item.get("version") for item in items if item.get("version")}
                available_versions = sorted(list(versions_set), reverse=True)
                versions_str = ", ".join(available_versions)
                
                if tag in available_versions:
                    result = {
                        "Status": "YES (Exact Match)", 
                        "URI": f"dp.apps.rancher.io/containers/{search_name}:{tag}", 
                        "Available_Versions": versions_str,
                        "Final_Slug": search_name
                    }
                else:
                    result = {
                        "Status": "YES (Upgrade Available)", 
                        "URI": f"dp.apps.rancher.io/containers/{search_name}:<New_Version>", 
                        "Available_Versions": versions_str,
                        "Final_Slug": search_name
                    }
            else:
                # Third defense line: AI inference fallback
                if not is_fallback and self.ollama and original_raw_name:
                    inferred_name = self.ollama.infer_true_name(original_raw_name)
                    
                    if inferred_name and inferred_name != search_name:
                        logging.info(f"\n🧠 AI Fallback Triggered: [{original_raw_name}] not found, trying [{inferred_name}]")
                        fallback_result = self.check_appco_image(inferred_name, tag, is_fallback=True)
                        
                        if fallback_result["Status"] != "NO (Not Found)" and fallback_result["Status"] != "ERROR":
                            self.cache[cache_key] = fallback_result
                            return fallback_result

                result = {"Status": "NO (Not Found)", "URI": "-", "Available_Versions": "-", "Final_Slug": search_name}
                
        except Exception:
            result = {"Status": "ERROR", "URI": "-", "Available_Versions": "-", "Final_Slug": search_name}
            
        self.cache[cache_key] = result
        return result


class RancherSecAnalyzer:
    def __init__(self, use_ai=False, ai_model=None):
        env_use_ai = os.getenv("USE_OLLAMA_AI", "false").lower() in ["true", "1", "yes"]
        final_use_ai = use_ai or env_use_ai
        
        self.ollama_client = OllamaClient(model_name=ai_model) if final_use_ai else None
        self.api_client = APIClient(ollama_client=self.ollama_client)
        self.scans_url = os.getenv("RANCHER_SCANS_URL", "https://scans.rancher.com/")
        self.include_head = os.getenv("INCLUDE_HEAD_RELEASES", "false").lower() in ["true", "1", "yes"]
        
        # System prefixes to strip
        self.system_prefixes = ["appco-", "mirrored-", "hardened-", "rancher-"]
        
        # Load aliases
        self.aliases = self._load_aliases()
        
        if final_use_ai:
            logging.info(f"🤖 AI inference enabled (Model: {self.ollama_client.model})")

    def _load_aliases(self):
        alias_file = os.getenv("ALIAS_FILE", "aliases.json")
        if os.path.exists(alias_file):
            try:
                with open(alias_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logging.info(f"📖 Successfully loaded aliases dictionary ({alias_file}) with {len(data)} rules.")
                    return data
            except Exception as e:
                logging.error(f"⚠️ Failed to load {alias_file}: {e}")
        return {}

    @staticmethod
    def parse_filename(filename):
        match = re.search(r'report-(.*?)-cves\.csv', filename)
        return match.group(1) if match else "Unknown_Version"

    def parse_image(self, image_raw_str):
        clean_str = re.sub(r'\s*\([^)]*\)', '', image_raw_str).strip()
        if ':' in clean_str:
            image_path, tag = clean_str.rsplit(':', 1)
        else:
            image_path = clean_str
            tag = "latest"
            
        original_name = image_path.split('/')[-1]
        search_name = original_name
        
        # Defense Line 1: Dynamic prefix stripping
        stripped = True
        while stripped:
            stripped = False
            for prefix in self.system_prefixes:
                if search_name.startswith(prefix):
                    search_name = search_name[len(prefix):]
                    stripped = True
                    break
            
        # Defense Line 2: Check JSON absolute whitelist
        if search_name in self.aliases:
            search_name = self.aliases[search_name]
            
        return original_name, search_name, tag

    def fetch_report_links(self, version_filter=None):
        logging.info(f"Connecting to {self.scans_url} to fetch report list...")
        if not self.include_head:
            logging.info("ℹ️ Filter enabled: Skipping '-head' releases.")
            
        res = self.api_client.session.get(self.scans_url, timeout=20)
        res.raise_for_status()
        
        soup = BeautifulSoup(res.text, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.endswith('.csv') and 'cves' in href:
                filename = os.path.basename(href)
                if not self.include_head and "-head" in filename.lower(): continue
                if version_filter and version_filter.lower() not in href.lower(): continue
                links.append((filename, urljoin(self.scans_url, href)))
        return links

    def generate_mapping(self, links, output_file):
        total_rows = 0
        header_written = False
        
        with open(output_file, mode='w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            pbar = tqdm(links, desc="Processing", unit="file", dynamic_ncols=True)
            
            for filename, url in pbar:
                release_ver = self.parse_filename(filename)
                pbar.set_postfix_str(f"Processing: {release_ver}")
                
                res = self.api_client.session.get(url, timeout=30)
                reader = csv.reader(res.content.decode('utf-8').splitlines())
                
                try: 
                    original_headers = next(reader)
                except StopIteration: 
                    continue
                
                if not header_written:
                    added_headers = ["AppCo_Status", "AppCo_Target_URI", "AppCo_Available_Versions", "Rancher_Release_Version", "Parsed_Image_Name", "Parsed_Tag"]
                    writer.writerow(added_headers + original_headers)
                    header_written = True
                
                # Identify column indexes dynamically
                img_idx = next((i for i, h in enumerate(original_headers) if h.lower() == "image"), -1)
                status_idx = next((i for i, h in enumerate(original_headers) if h.lower() == "status"), -1)
                
                if img_idx == -1: 
                    continue
                
                for row in reader:
                    if not row or len(row) <= img_idx: 
                        continue
                        
                    # Filter out 'not_affected' vulnerabilities
                    if status_idx != -1 and len(row) > status_idx:
                        if row[status_idx].strip().lower() == "not_affected":
                            continue

                    raw_img = row[img_idx].strip()
                    if raw_img.upper() == "IMAGE" or not raw_img: 
                        continue
                    
                    original_name, search_name, app_tag = self.parse_image(raw_img)
                    
                    appco_res = self.api_client.check_appco_image(search_name, app_tag, original_raw_name=original_name)
                    
                    new_row = [
                        appco_res["Status"], appco_res["URI"], appco_res["Available_Versions"], 
                        release_ver, appco_res["Final_Slug"], app_tag
                    ] + row
                    
                    writer.writerow(new_row)
                    total_rows += 1
                    
        logging.info(f"\n✅ Mapping report generated! (Total {total_rows} records) -> {output_file}")

    def generate_summary(self, mapping_file, output_file):
        if not os.path.exists(mapping_file): return
        
        logging.info("Calculating residual risk summary...")
        stats = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
        total_remaining = 0
        
        with open(mapping_file, mode='r', encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                if not row.get("AppCo_Status", "").startswith("YES"):
                    rel = row.get("Rancher_Release_Version", "Unknown")
                    app = row.get("Parsed_Image_Name", "Unknown")
                    ver = row.get("Parsed_Tag", "Unknown")
                    sev = row.get("severity", "UNKNOWN").upper()
                    cve = row.get("vulnerability_id", "Unknown")
                    
                    if cve not in stats[rel][app][ver][sev]:
                        stats[rel][app][ver][sev].append(cve)
                        total_remaining += 1

        headers = ["Rancher_Release_Version", "Application_Name", "Application_Version", "Severity", "Remaining_CVE_Count", "CVE_List"]
        with open(output_file, mode='w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for rel in sorted(stats.keys()):
                for app in sorted(stats[rel].keys()):
                    for ver in sorted(stats[rel][app].keys()):
                        for sev, cves in stats[rel][app][ver].items():
                            cves.sort(reverse=True)
                            writer.writerow({
                                "Rancher_Release_Version": rel, "Application_Name": app, 
                                "Application_Version": ver, "Severity": sev, 
                                "Remaining_CVE_Count": len(cves), "CVE_List": ", ".join(cves)
                            })
                            
        logging.info(f"✅ Residual risk summary generated! ({total_remaining} unique unmitigated vulnerabilities) -> {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Rancher CVE vs SUSE AppCo (Enterprise Hybrid Edition)")
    parser.add_argument("-v", "--version", type=str, help="Filter by Rancher/K8s version (e.g., rancher-v2.14)", default="")
    parser.add_argument("-m", "--mapping-out", type=str, help="Output filename for the mapping report", default="rancher_mapping_full.csv")
    parser.add_argument("-s", "--summary-out", type=str, help="Output filename for the summary report", default="rancher_summary.csv")
    
    parser.add_argument("--use-ai", action="store_true", help="Force enable Ollama AI inference (can be set via .env)")
    parser.add_argument("--ai-model", type=str, default=None, help="Override Ollama model name (can be set via .env)")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    analyzer = RancherSecAnalyzer(use_ai=args.use_ai, ai_model=args.ai_model)
    links = analyzer.fetch_report_links(version_filter=args.version)
    if links:
        analyzer.generate_mapping(links, args.mapping_out)
        analyzer.generate_summary(args.mapping_out, args.summary_out)
    else:
        logging.warning("No matching scan reports found.")

if __name__ == "__main__":
    main()
