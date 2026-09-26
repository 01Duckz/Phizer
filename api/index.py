from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import email
from email import policy
import re
from urllib.parse import urlparse
import urllib.request
import urllib.error
import os
import json

app = FastAPI(title="Phizer SOC Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024

def check_virustotal(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "unconfigured", "message": "API Key Missing", "details": []}

    req_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    req = urllib.request.Request(req_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})

    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                results = attributes.get("last_analysis_results", {})
                
                malicious_details = [
                    {"vendor": vendor, "result": res.get("result", "Malicious")}
                    for vendor, res in results.items()
                    if res.get("category") == "malicious"
                ]

                return {
                    "malicious": stats.get("malicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "status": "scored",
                    "details": malicious_details
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "clean", "message": "Clean / Unflagged", "details": []}
        elif e.code == 429:
            return {"status": "rate_limited", "message": "Quota Exceeded", "details": []}
    except Exception:
        pass

    return {"status": "unknown", "message": "Lookup Unavailable", "details": []}

@app.post("/api")
@app.post("/api/index")
async def analyze_eml(file: UploadFile = File(...)):
    contents = await file.read()

    if len(contents) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File size exceeds 10MB limit.")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        msg = email.message_from_bytes(contents, policy=policy.default)

        # 1. Extract All Headers
        all_headers = [{"name": key, "value": str(val)} for key, val in msg.items()]

        # 2. Extract Relay Information (Received Headers)
        received_headers = msg.get_all("Received") or []
        relays = []
        for i, header in enumerate(reversed(received_headers)):
            relays.append({
                "hop": i + 1,
                "detail": str(header).strip().replace("\n", " ")
            })

        # 3. Authentication & Spoofing
        auth_header = str(msg.get("Authentication-Results", "No Authentication-Results header found."))
        spf_match = re.search(r"spf=(\w+)", auth_header, re.IGNORECASE)
        dkim_match = re.search(r"dkim=(\w+)", auth_header, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(\w+)", auth_header, re.IGNORECASE)

        auth_results = {
            "spf": spf_match.group(1).upper() if spf_match else "NONE",
            "dkim": dkim_match.group(1).upper() if dkim_match else "NONE",
            "dmarc": dmarc_match.group(1).upper() if dmarc_match else "NONE",
            "raw_basis": auth_header
        }

        from_hdr = str(msg.get("From", "N/A"))
        from_addr_match = re.search(r"[\w\.-]+@[\w\.-]+", from_hdr)
        from_addr = from_addr_match.group(0) if from_addr_match else from_hdr
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        
        return_path = str(msg.get("Return-Path", "")).strip("<>")
        return_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""

        is_spoofed = False
        evidence = []

        if auth_results["dmarc"] == "FAIL":
            is_spoofed = True
            evidence.append("DMARC Failed: Sender failed both alignment and SPF/DKIM verification.")
        
        if auth_results["spf"] == "FAIL" and auth_results["dmarc"] != "PASS":
            is_spoofed = True
            evidence.append("SPF Failed: Sending IP address is not listed in domain's SPF record.")

        if auth_results["dkim"] == "FAIL" and auth_results["dmarc"] != "PASS":
            is_spoofed = True
            evidence.append("DKIM Failed: Signature is invalid or message was modified in transit.")

        if auth_results["dmarc"] == "NONE" and auth_results["spf"] == "NONE" and auth_results["dkim"] == "NONE":
            if return_domain and from_domain:
                if not (return_domain == from_domain or return_domain.endswith("." + from_domain) or from_domain.endswith("." + return_domain)):
                    is_spoofed = True
                    evidence.append(f"Domain Mismatch: 'From' domain ({from_domain}) differs from 'Return-Path' ({return_domain}).")

        # 4. Extract URLs & VirusTotal
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload: body += payload.decode(errors="ignore")
                    except Exception: pass
        else:
            payload = msg.get_payload(decode=True)
            if payload: body = payload.decode(errors="ignore")

        raw_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        sanitized_urls = list(set([u.rstrip(".,;)'\"") for u in raw_urls]))[:10]

        url_reports = []
        for u in sanitized_urls:
            domain = urlparse(u).netloc
            if domain:
                url_reports.append({
                    "url": u,
                    "domain": domain,
                    "vt_reputation": check_virustotal(domain)
                })

        return {
            "metadata": {
                "subject": str(msg.get("Subject", "N/A")),
                "from": from_hdr,
                "date": str(msg.get("Date", "N/A")),
                "return_path": return_path or "N/A",
            },
            "security_checks": {
                "spoofing_flagged": is_spoofed,
                "authentication": auth_results,
                "evidence": evidence,
            },
            "urls": url_reports,
            "headers": all_headers,
            "relays": relays
        }

    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))