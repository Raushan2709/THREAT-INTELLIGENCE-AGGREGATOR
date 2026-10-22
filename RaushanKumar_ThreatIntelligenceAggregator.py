#!/usr/bin/env python3
"""
Project: Threat Intelligence Aggregator
Author: Raushan Kumar
Bootcamp: IBM SkillsBuild Cyber Security BootCamp 2026 (BharatCares)
Description: A Python CLI tool to aggregate live Indicators of Compromise (IoCs) 
             from VirusTotal and AlienVault OTX APIs.
"""

import sys
import argparse
import requests
import json
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# API Endpoints
VT_API_URL = "https://www.virustotal.com/api/v3/search?query="
OTX_API_URL = "https://otx.alienvault.com/api/v1/indicators"

def banner():
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "       THREAT INTELLIGENCE AGGREGATOR - SOC TOOL")
    print(Fore.CYAN + Style.BRIGHT + "       IBM SkillsBuild Cyber Security Bootcamp 2026")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60 + "\n")

def query_virustotal(ioc, api_key):
    if not api_key:
        return {"error": "VirusTotal API key not provided."}
    
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{ioc}" if len(ioc) in [32, 64] else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}" if "." in ioc and not ioc.isalpha() else f"https://www.virustotal.com/api/v3/domains/{ioc}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "status": "Success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
        elif response.status_code == 404:
            return {"source": "VirusTotal", "status": "Not Found", "malicious": 0}
        else:
            return {"source": "VirusTotal", "status": f"Error: HTTP {response.status_code}", "malicious": 0}
    except Exception as e:
        return {"source": "VirusTotal", "status": f"Exception: {str(e)}", "malicious": 0}

def query_alienvault(ioc):
    ioc_type = "ip" if "." in ioc and not ioc.isalpha() else "domain" if "." in ioc else "hash"
    url = f"{OTX_API_URL}/{ioc_type}/{ioc}/general"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            return {
                "source": "AlienVault OTX",
                "status": "Success",
                "pulse_count": pulse_info.get("count", 0),
                "references": pulse_info.get("references", [])
            }
        elif response.status_code == 404:
            return {"source": "AlienVault OTX", "status": "Not Found", "pulse_count": 0}
        else:
            return {"source": "AlienVault OTX", "status": f"Error: HTTP {response.status_code}", "pulse_count": 0}
    except Exception as e:
        return {"source": "AlienVault OTX", "status": f"Exception: {str(e)}", "pulse_count": 0}

def main():
    banner()
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator for IoC Triage")
    parser.add_argument("-i", "--ioc", required=True, help="Indicator of Compromise (IP, Domain, or Hash)")
    parser.add_argument("-k", "--vt-key", help="VirusTotal API Key", default="")
    
    args = parser.parse_args()
    ioc = args.ioc
    
    print(Fore.YELLOW + f"[*] Analyzing IoC: {ioc}\n")
    
    vt_result = query_virustotal(ioc, args.vt_key)
    print(Fore.GREEN + "[+] VirusTotal Results:")
    print(json.dumps(vt_result, indent=4))
    
    print("-" * 40)
    
    otx_result = query_alienvault(ioc)
    print(Fore.GREEN + "[+] AlienVault OTX Results:")
    print(json.dumps(otx_result, indent=4))
    
    print(Fore.CYAN + "\n[+] Analysis complete.")

if __name__ == "__main__":
    main()