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

ALLOWED_EXTENSIONS = (".eml",)

# Browsers/OSes are inconsistent about what Content-Type they report for .eml
# files, so this is a permissive allow-list rather than a strict check.
ALLOWED_CONTENT_TYPES = {
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
    "application/eml",
    "",  # some clients omit it entirely
}

# At least one of these should appear near the top of a genuine RFC 5322
# email if it's actually an .eml file and not just something renamed to
# look like one.
EMAIL_HEADER_SIGNATURES = (
    "from:", "to:", "subject:", "date:", "received:",
    "return-path:", "message-id:", "mime-version:",
)

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
                
                # Fetch total vendor count to fix the "2/0" bug
                total_vendors = len(results.keys())
                
                malicious_details = [
                    {"vendor": vendor, "result": res.get("result", "Malicious")}
                    for vendor, res in results.items()
                    if res.get("category") == "malicious"
                ]

                return {
                    "malicious": stats.get("malicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": total_vendors, 
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
    # --- 1. Filename / extension validation ---
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    filename_lower = file.filename.lower()
    if not filename_lower.endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .eml files are accepted."
        )

    # --- 2. Content-Type validation (best-effort; extension is the source of truth) ---
    if file.content_type and file.content_type.lower() not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported content type '{file.content_type}'. Expected a raw email (.eml) file."
        )

    contents = await file.read()

    # --- 3. Size validation ---
    if len(contents) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File size exceeds 10MB limit.")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # --- 4. Structural validation: reject files that aren't actually emails, ---
    #        even if they were named/labeled like one.
    preview = contents[:4096].decode("utf-8", errors="ignore").lower()
    if not any(sig in preview for sig in EMAIL_HEADER_SIGNATURES):
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be a valid email (.eml) file."
        )

    try:
        msg = email.message_from_bytes(contents, policy=policy.default)

        # 1. Extract All Headers
        all_headers = [{"name": key, "value": str(val)} for key, val in msg.items()]

        if not all_headers:
            raise HTTPException(
                status_code=400,
                detail="File does not contain any valid email headers."
            )

        # 2. Extract Relay Information (Fixed Parsing logic)
        received_headers = msg.get_all("Received") or []
        relays = []
        for i, header in enumerate(reversed(received_headers)):
            h_str = str(header).replace("\n", " ").replace("\r", " ").replace("\t", " ").strip()
            
            # Use Regex to dynamically extract relay node details
            from_match = re.search(r"from\s+([^\s]+)", h_str, re.IGNORECASE)
            by_match = re.search(r"by\s+([^\s;]+)", h_str, re.IGNORECASE)
            with_match = re.search(r"with\s+([^\s;]+)", h_str, re.IGNORECASE)
            date_part = h_str.split(";")[-1].strip() if ";" in h_str else "-"

            relays.append({
                "hop": i + 1,
                "from": from_match.group(1) if from_match else "Unknown",
                "by": by_match.group(1) if by_match else "Unknown",
                "with": with_match.group(1) if with_match else "-",
                "time": date_part,
                "delay": "-", # Delay math requires timezone calc, leaving blank to keep it secure/stable
                "raw": h_str
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

        # 4. Extract URLs
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

    except HTTPException:
        # Preserve validation errors (400/413) raised above instead of
        # masking them as a generic 500.
        raise
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))