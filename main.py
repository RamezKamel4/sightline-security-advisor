from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nmap # type: ignore
import requests # For NVD API
import urllib.parse # For URL encoding search terms
import os # To access environment variables
from dotenv import load_dotenv # Add this import
from openai import OpenAI # For OpenAI API

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import traceback

# Load environment variables from .env file
load_dotenv()

print(f"Attempting to load .env. Key found: {os.getenv('OPENAI_API_KEY')}")

# --- OpenAI API Key Configuration ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    print("WARNING: OpenAI API key is not set in the environment or .env file.")
    OPENAI_API_KEY = "YOUR_OPENAI_API_KEY_FALLBACK_IF_NOT_SET"

# Initialize client
client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI()

app.mount("/", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    ip: str
    nmap_args: str = "-T4"  # Default nmap arguments
    scan_profile: str = "basic"  # Scan profile for reference

@app.get("/")
async def read_root():
    return {"message": "VulnScan AI Backend is running"}

def get_gpt_explanation_and_fix(cve_id: str, cve_description: str) -> dict:
    if OPENAI_API_KEY == "YOUR_OPENAI_API_KEY_FALLBACK_IF_NOT_SET" or not OPENAI_API_KEY:
        return {
            "gpt_explanation": "OpenAI API key not configured. Please set the OPENAI_API_KEY environment variable or in .env file.",
            "recommended_fix": "OpenAI API key not configured. Please set the OPENAI_API_KEY environment variable or in .env file."
        }
    try:
        system_prompt = "You are a cybersecurity expert. Your task is to explain the CVE (Common Vulnerabilities and Exposures) provided and suggest a concise, actionable fix. Focus on practical steps for system administrators or developers."
        user_prompt = f"CVE ID: {cve_id}\nDescription: {cve_description}\n\nPlease provide:\n1. A brief explanation of this vulnerability.\n2. A recommended, actionable fix."

        response = client.chat.completions.create(
            model="gpt-4", # Consider "gpt-3.5-turbo" for faster, cheaper responses if acceptable.
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=350, # Increased token limit for potentially more detailed fixes
            temperature=0.3 # Lower temperature for more deterministic and factual output
        )

        content = response.choices[0].message.content

        gpt_explanation = "Could not parse explanation from GPT response."
        recommended_fix = "Could not parse recommended fix from GPT response."

        if content:
            # Attempt to split based on common patterns GPT might use for "Explanation:" and "Recommended Fix:"
            # This parsing logic might need to be adjusted based on observed GPT outputs.
            content_lower = content.lower()
            explanation_marker = "explanation:"
            fix_marker = "recommended fix:" # More flexible marker

            explanation_start = content_lower.find(explanation_marker)
            fix_start = content_lower.find(fix_marker)

            if explanation_start != -1 and fix_start != -1:
                explanation_end = fix_start if explanation_start < fix_start else len(content)
                gpt_explanation = content[explanation_start + len(explanation_marker):explanation_end].strip()

                recommended_fix = content[fix_start + len(fix_marker):].strip()
                # Remove potential leading list numbers like "1. ", "2. " from parsed sections
                gpt_explanation = gpt_explanation.lstrip('1. ')
                recommended_fix = recommended_fix.lstrip('2. ')

            elif content_lower.startswith("explanation:") or content_lower.startswith("1. explanation:"): # If only explanation is found or is primary
                 gpt_explanation = content.split("\n",1)[0] # take first line as explanation
                 recommended_fix = content.split("\n",1)[1] if "\n" in content else "No specific fix parsed, see explanation."


            else: # Fallback if specific markers are not found
                split_content = content.split("\n\n", 1) # Try splitting by double newline
                gpt_explanation = split_content[0].strip()
                if len(split_content) > 1:
                    recommended_fix = split_content[1].strip()
                else:
                    recommended_fix = "No specific fix provided in a separate section."

        return {
            "gpt_explanation": gpt_explanation,
            "recommended_fix": recommended_fix
        }
    except Exception as e:
        print(f"Error calling OpenAI API for {cve_id}: {e}")
        return {
            "gpt_explanation": f"Error generating explanation via OpenAI: {e}",
            "recommended_fix": f"Error generating fix via OpenAI: {e}"
        }

def fetch_cves_for_service(service_name: str, version: str) -> list:
    cves_list = []
    if not service_name or service_name == 'unknown': # Allow search even if version is unknown
        return cves_list

    # Construct search query: prefer service_name and version if both are present and known
    search_query_parts = []
    if service_name and service_name != 'unknown':
        search_query_parts.append(service_name)
    if version and version != 'unknown':
        search_query_parts.append(version)

    if not search_query_parts: # Should not happen due to earlier check, but as a safeguard
        return cves_list

    search_query = " ".join(search_query_parts)
    encoded_query = urllib.parse.quote(search_query)
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}&resultsPerPage=10" # Limit results
    headers = {'User-Agent': 'VulnScanAI/1.0'}

    try:
        response = requests.get(nvd_api_url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        if 'vulnerabilities' in data:
            for item_wrapper in data['vulnerabilities']:
                cve_item = item_wrapper['cve']
                cve_id = cve_item['id']
                description = "No English description available."
                if cve_item.get('descriptions'):
                    for desc_entry in cve_item['descriptions']:
                        if desc_entry['lang'] == 'en':
                            description = desc_entry['value']
                            break

                severity = "N/A"
                if 'metrics' in cve_item:
                    if 'cvssMetricV31' in cve_item['metrics'] and cve_item['metrics']['cvssMetricV31']:
                        severity = cve_item['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    elif 'cvssMetricV30' in cve_item['metrics'] and cve_item['metrics']['cvssMetricV30']:
                        severity = cve_item['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    elif 'cvssMetricV2' in cve_item['metrics'] and cve_item['metrics']['cvssMetricV2']:
                        severity = cve_item['metrics']['cvssMetricV2'][0]['baseSeverity']

                published_date = cve_item['published']

                # Get GPT explanation and fix, only if not a fallback key
                gpt_data = {"gpt_explanation": "OpenAI API key not configured. Please set the OPENAI_API_KEY environment variable or in .env file.", "recommended_fix": "OpenAI API key not configured. Please set the OPENAI_API_KEY environment variable or in .env file."}
                if OPENAI_API_KEY != "YOUR_OPENAI_API_KEY_FALLBACK_IF_NOT_SET" and OPENAI_API_KEY:
                    gpt_data = get_gpt_explanation_and_fix(cve_id, description)

                cves_list.append({
                    "id": cve_id,
                    "description": description,
                    "severity": severity,
                    "published": published_date,
                    "gpt_explanation": gpt_data["gpt_explanation"],
                    "recommended_fix": gpt_data["recommended_fix"]
                })
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs for '{search_query}': {e}")
        return [{"error": f"Could not fetch CVEs: {e}", "query": search_query}]
    except KeyError as e:
        print(f"KeyError parsing CVE data for '{search_query}': {e} - Data: {data}")
        return [{"error": f"Error parsing CVE data: {e}", "query": search_query}]
    return cves_list

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import traceback

@app.post("/api/scan")
async def scan_ip(request: ScanRequest):
    ip_address = request.ip
    nmap_args = request.nmap_args
    scan_profile = request.scan_profile
    
    print(f"Starting scan on {ip_address} with profile: {scan_profile}, args: {nmap_args}")
    
    nm = nmap.PortScanner()
    results = []

    try:
        # Use the provided nmap arguments for the scan
        nm.scan(ip_address, arguments=nmap_args)
    except nmap.PortScannerError as e:
        print("Nmap Scanner Error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Nmap scan error: {e}")
    except Exception as e:
        print("Unexpected Nmap error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during Nmap scan: {e}")

    if not nm.all_hosts():
        raise HTTPException(status_code=404, detail=f"Host {ip_address} not found or not scannable.")

    host = nm.all_hosts()[0]
    if host not in nm or 'tcp' not in nm[host]:
        return {"message": f"No open TCP ports found on {ip_address} or host did not respond to scan probes."}

    for port in nm[host]['tcp']:
        port_info = nm[host]['tcp'][port]
        service_name = port_info.get('name', 'unknown')
        product = port_info.get('product', '').strip()
        version_str = port_info.get('version', '').strip()

        search_service_name = product if product else service_name
        search_version = version_str if version_str else "unknown"
        display_version = f"{product} {version_str}".strip() if product or version_str else 'unknown'
        if not display_version:
            display_version = 'unknown'

        service_data = {
            "port": port,
            "service": service_name,
            "version": display_version,
            "cves": []
        }

        # Try CVE fetching with detailed debug logging
        if search_service_name != 'unknown':
            try:
                print(f"Fetching CVEs for: {search_service_name} {search_version}")
                cves = fetch_cves_for_service(search_service_name, search_version)
                service_data["cves"] = cves
            except Exception as e:
                print("⚠️ Error while fetching CVEs:", e)
                traceback.print_exc()
                service_data["cves"] = ["Error fetching CVEs"]

        results.append(service_data)

    if not results:
        return {"message": f"No services with version information found on {ip_address}."}

    print(f"Scan completed. Found {len(results)} services.")
    return results
