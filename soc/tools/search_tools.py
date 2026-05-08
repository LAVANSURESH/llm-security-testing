"""Simulated threat intelligence search and lookup tools for SOC agents."""

import json
import re

# Simulated CVE database
CVE_DB = {
    "CVE-2021-44228": {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Apache Log4j2 JNDI injection vulnerability allowing RCE",
        "affected": ["Apache Log4j 2.0-beta9 to 2.14.1"],
        "mitre_ttps": ["T1190", "T1059"],
    },
    "CVE-2021-26855": {
        "id": "CVE-2021-26855",
        "name": "ProxyLogon",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Microsoft Exchange Server SSRF vulnerability",
        "affected": ["Exchange Server 2013-2019"],
        "mitre_ttps": ["T1190", "T1505.003"],
    },
    "CVE-2023-34362": {
        "id": "CVE-2023-34362",
        "name": "MOVEit SQLi",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "SQL injection in MOVEit Transfer leading to RCE",
        "affected": ["MOVEit Transfer before 2023.0.1"],
        "mitre_ttps": ["T1190", "T1078"],
    },
}

# Simulated threat intel IOC database
MALICIOUS_IOCS = {
    "192.168.1.99": {"type": "ip", "tags": ["c2", "cobalt_strike"], "confidence": 0.9, "actor": "APT29"},
    "10.0.0.254": {"type": "ip", "tags": ["scanner", "recon"], "confidence": 0.7, "actor": "unknown"},
    "malware.evil.com": {"type": "domain", "tags": ["c2", "malware"], "confidence": 0.95, "actor": "APT41"},
    "185.220.101.50": {"type": "ip", "tags": ["tor_exit", "anonymizer"], "confidence": 0.85, "actor": "unknown"},
    "d41d8cd98f00b204e9800998ecf8427e": {"type": "md5", "tags": ["ransomware", "lockbit"], "confidence": 0.99, "actor": "LockBit"},
}

# MITRE ATT&CK TTP reference
MITRE_TTPS = {
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access / Persistence", "description": "Adversaries use valid accounts to maintain persistence and evade defenses"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force techniques to gain access to accounts"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "description": "Attempting to guess passwords without prior knowledge"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "description": "Using a single password against many accounts"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on target systems to interrupt availability (ransomware)"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries abuse command and script interpreters to execute commands"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "Adversaries transfer tools or other files from an external system"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "description": "Adversaries use SMB for lateral movement via admin shares"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "description": "Adversaries exploit vulnerabilities to elevate privileges"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries exploit vulnerabilities in internet-facing software"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Adversaries steal data by exfiltrating it over the C2 channel"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries send spearphishing emails with malicious attachments"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion / Privilege Escalation", "description": "Adversaries inject code into processes to evade defenses and elevate privileges"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Adversaries attempt to dump credentials to obtain usernames and passwords"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion", "description": "Adversaries disable security tools to avoid detection"},
}


def lookup_cve(cve_id: str) -> dict:
    """Look up CVE details from the simulated database."""
    cve_id = cve_id.upper().strip()
    if cve_id in CVE_DB:
        return {"found": True, "cve": CVE_DB[cve_id]}
    return {
        "found": False,
        "cve_id": cve_id,
        "message": f"CVE {cve_id} not found in local database. Check NVD for details.",
    }


def search_threat_intel(ioc: str) -> dict:
    """Check if an IOC is known malicious."""
    ioc = ioc.strip()
    if ioc in MALICIOUS_IOCS:
        entry = MALICIOUS_IOCS[ioc]
        return {
            "found": True,
            "ioc": ioc,
            "malicious": True,
            "tags": entry["tags"],
            "confidence": entry["confidence"],
            "threat_actor": entry["actor"],
        }
    # Check for partial IP range matches
    for known_ioc in MALICIOUS_IOCS:
        if known_ioc in ioc or ioc in known_ioc:
            entry = MALICIOUS_IOCS[known_ioc]
            return {
                "found": True,
                "ioc": ioc,
                "malicious": True,
                "matched": known_ioc,
                "tags": entry["tags"],
                "confidence": entry["confidence"] * 0.8,
                "threat_actor": entry["actor"],
            }
    return {
        "found": False,
        "ioc": ioc,
        "malicious": False,
        "message": "IOC not found in threat intelligence database",
    }


def get_mitre_ttp(ttp_id: str) -> dict:
    """Get MITRE ATT&CK TTP details."""
    ttp_id = ttp_id.upper().strip()
    if ttp_id in MITRE_TTPS:
        return {"found": True, "ttp_id": ttp_id, **MITRE_TTPS[ttp_id]}
    return {"found": False, "ttp_id": ttp_id, "message": f"TTP {ttp_id} not found"}


def enrich_ip(ip: str) -> dict:
    """Enrich an IP address with geo and reputation data (simulated)."""
    intel = search_threat_intel(ip)
    # Simulate geolocation
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        geo = {"country": "Internal", "org": "Local Network", "is_private": True}
    elif ip.startswith("185."):
        geo = {"country": "RU", "org": "Hosting Provider", "is_private": False}
    elif ip.startswith("45."):
        geo = {"country": "CN", "org": "Unknown ASN", "is_private": False}
    else:
        geo = {"country": "US", "org": "Cloudflare", "is_private": False}

    return {
        "ip": ip,
        "geo": geo,
        "threat_intel": intel,
        "reputation_score": 0.1 if intel.get("malicious") else 0.8,
    }


def correlate_iocs(ioc_list: list) -> dict:
    """Correlate a list of IOCs to find connections."""
    results = []
    malicious_count = 0
    threat_actors = set()

    for ioc in ioc_list:
        intel = search_threat_intel(ioc)
        results.append(intel)
        if intel.get("malicious"):
            malicious_count += 1
            actor = intel.get("threat_actor")
            if actor and actor != "unknown":
                threat_actors.add(actor)

    return {
        "total_iocs": len(ioc_list),
        "malicious_count": malicious_count,
        "clean_count": len(ioc_list) - malicious_count,
        "threat_actors": list(threat_actors),
        "correlated_campaign": len(threat_actors) == 1,
        "results": results,
    }


def extract_iocs_from_text(text: str) -> dict:
    """Extract potential IOCs (IPs, domains, hashes) from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

    ips = list(set(re.findall(ip_pattern, text)))
    domains = list(set(re.findall(domain_pattern, text)))
    md5s = list(set(re.findall(md5_pattern, text)))
    sha256s = list(set(re.findall(sha256_pattern, text)))
    urls = list(set(re.findall(url_pattern, text)))

    # Filter out common false positives
    domains = [d for d in domains if '.' in d and not d.endswith('.log') and not d.endswith('.py')]

    return {
        "ips": ips,
        "domains": domains,
        "md5_hashes": md5s,
        "sha256_hashes": sha256s,
        "urls": urls,
        "total": len(ips) + len(domains) + len(md5s) + len(sha256s),
    }
