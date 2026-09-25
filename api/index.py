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

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
MAX_URLS_TO_CHECK = 10                # VirusTotal rate-limit protection


def check_virustotal(domain: str) -> dict:
    """Query VirusTotal API v3 for domain reputation."""
    if not VIRUSTOTAL_API_KEY:
        return {"status": "unconfigured", "message": "API Key Missing"}

    req_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    req = urllib.request.Request(
        req_url, 
        headers={"x-apikey": VIRUSTOTAL_API_KEY}
    )

    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "status": "scored",
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "clean", "message": "Clean / Unflagged"}
        elif e.code == 429:
            return {"status": "rate_limited", "message": "Quota Exceeded"}
    except Exception:
        pass

    return {"status": "unknown", "message": "Lookup Unavailable"}


@app.post("/api")
@app.post("/api/index")
async def analyze_eml(file: UploadFile = File(...)):
    """Accepts an .eml upload, analyzes authentication headers, detects spoofing,

    generates evidence, and queries VirusTotal for embedded link domains.

    """
    contents = await file.read()

    if len(contents) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File size exceeds 10MB limit.")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        msg = email.message_from_bytes(contents, policy=policy.default)

        subject = str(msg.get("Subject", "N/A"))
        from_hdr = str(msg.get("From", "N/A"))
        date_hdr = str(msg.get("Date", "N/A"))
        return_path = str(msg.get("Return-Path", "")).strip("<>")

        # Extract domains for alignment checks
        from_addr_match = re.search(r"[\w\.-]+@[\w\.-]+", from_hdr)
        from_addr = from_addr_match.group(0) if from_addr_match else from_hdr
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        return_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""

        # Parse Authentication Headers
        auth_header = str(msg.get("Authentication-Results", ""))
        spf_match = re.search(r"spf=(\w+)", auth_header, re.IGNORECASE)
        dkim_match = re.search(r"dkim=(\w+)", auth_header, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(\w+)", auth_header, re.IGNORECASE)

        auth_results = {
            "spf": spf_match.group(1).upper() if spf_match else "NONE",
            "dkim": dkim_match.group(1).upper() if dkim_match else "NONE",
            "dmarc": dmarc_match.group(1).upper() if dmarc_match else "NONE",
        }

        # Enhanced Spoofing & Proof Logic
        is_spoofed = False
        evidence = []

        # 1. DMARC Evaluation
        if auth_results["dmarc"] == "PASS":
            evidence.append("DMARC Passed: The domain owner explicitly authorized this sender.")
        elif auth_results["dmarc"] == "FAIL":
            is_spoofed = True
            evidence.append("DMARC Failed: Sender failed both alignment and SPF/DKIM verification.")

        # 2. SPF & DKIM Evaluation
        if auth_results["spf"] == "PASS":
            evidence.append("SPF Passed: Sending IP address is authorized in DNS records.")
        elif auth_results["spf"] == "FAIL":
            if auth_results["dmarc"] != "PASS":
                is_spoofed = True
            evidence.append("SPF Failed: Sending IP address is not listed in domain's SPF record.")

        if auth_results["dkim"] == "PASS":
            evidence.append("DKIM Passed: Cryptographic signature verified against public key.")
        elif auth_results["dkim"] == "FAIL":
            if auth_results["dmarc"] != "PASS":
                is_spoofed = True
            evidence.append("DKIM Failed: Signature is invalid or message was modified in transit.")

        # 3. Domain Alignment Fallback (when auth records are missing)
        if auth_results["dmarc"] == "NONE" and auth_results["spf"] == "NONE" and auth_results["dkim"] == "NONE":
            if return_domain and from_domain:
                if not (return_domain == from_domain or 
                        return_domain.endswith("." + from_domain) or 
                        from_domain.endswith("." + return_domain)):
                    is_spoofed = True
                    evidence.append(f"Domain Mismatch: 'From' domain ({from_domain}) differs from 'Return-Path' ({return_domain}) without authentication headers.")
                else:
                    evidence.append("Domain Alignment: 'From' and 'Return-Path' domains match.")
            else:
                evidence.append("Incomplete Headers: Missing authentication and Return-Path information.")

        # Extract Body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(errors="ignore")
                    except Exception:
                        pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")

        # Extract URLs
        raw_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        sanitized_urls = list(set([u.rstrip(".,;)'\"") for u in raw_urls]))[:MAX_URLS_TO_CHECK]

        # Reputation Lookup
        url_reports = []
        checked_domains = {}

        for u in sanitized_urls:
            domain = urlparse(u).netloc
            if not domain:
                continue

            if domain not in checked_domains:
                vt_score = check_virustotal(domain)
                checked_domains[domain] = vt_score
            else:
                vt_score = checked_domains[domain]

            url_reports.append({
                "url": u,
                "domain": domain,
                "vt_reputation": vt_score
            })

        return {
            "metadata": {
                "subject": subject,
                "from": from_hdr,
                "date": date_hdr,
                "return_path": return_path or "N/A",
            },
            "security_checks": {
                "spoofing_flagged": is_spoofed,
                "authentication": auth_results,
                "evidence": evidence,
            },
            "urls": url_reports,
        }

    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Error parsing email file: {str(err)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)