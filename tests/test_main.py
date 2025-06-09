import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock
import requests # Import for requests.exceptions.HTTPError

# Import the FastAPI app instance
# Ensure your main.py can be imported (e.g., by being in the PYTHONPATH)
# For this subtask, assume main.py is in the root and tests is a subdir.
# If not, adjust sys.path or how 'app' is imported.
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import app, client as main_openai_client # import client for patching

# Mocked Nmap Scan Results
MOCK_NMAP_RESULTS_SINGLE_HOST_OPEN_PORTS = {
    '127.0.0.1': {
        'tcp': {
            22: {'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1 Ubuntu 4ubuntu0.1'},
            80: {'name': 'http', 'product': 'Apache httpd', 'version': '2.4.46'},
        },
        'status': {'state': 'up'},
        'hostnames': [{'name': 'localhost', 'type': 'PTR'}]
    }
}

MOCK_NMAP_RESULTS_HOST_DOWN = {} # No hosts found
MOCK_NMAP_RESULTS_NO_OPEN_PORTS = {
     '127.0.0.1': {
        'tcp': {}, # No open TCP ports
        'status': {'state': 'up'},
        'hostnames': [{'name': 'localhost', 'type': 'PTR'}]
    }
}


# Asynchronous test functions using pytest-asyncio (implicitly handled by pytest with async functions)
@pytest.mark.asyncio
async def test_scan_ip_success():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class, \
         patch('main.requests.get') as mock_requests_get, \
         patch.object(main_openai_client.chat.completions, 'create') as mock_openai_create: # Patch the create method on the imported client instance

        # Configure mock for nmap
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None # scan method doesn't return the data directly
        mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
        mock_scanner_instance.__contains__.return_value = True # Ensures 'host in nm' check passes
        # This makes nm[host] work:
        mock_scanner_instance.__getitem__.return_value = MOCK_NMAP_RESULTS_SINGLE_HOST_OPEN_PORTS['127.0.0.1']
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        # Configure mock for NVD API (requests.get)
        mock_nvd_response = MagicMock()
        mock_nvd_response.status_code = 200
        mock_nvd_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-1234",
                    "descriptions": [{"lang": "en", "value": "Test CVE description"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                    "published": "2021-01-01T00:00:00.000"
                }
            }]
        }
        mock_requests_get.return_value = mock_nvd_response

        # Configure mock for OpenAI API
        mock_openai_message = MagicMock()
        mock_openai_message.content = "Explanation: Test explanation. Recommended Fix: Test fix."
        mock_openai_choice = MagicMock()
        mock_openai_choice.message = mock_openai_message
        mock_openai_response = MagicMock()
        mock_openai_response.choices = [mock_openai_choice]
        mock_openai_create.return_value = mock_openai_response

        # Ensure OPENAI_API_KEY is set for the test to run the OpenAI part
        # Also patch the global OPENAI_API_KEY in main.py for the duration of this test
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}), \
             patch('main.OPENAI_API_KEY', "test_key"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post("/api/scan", json={"ip": "127.0.0.1"})

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2 # Two ports

        # Check port 22 (ssh)
        assert data[0]["port"] == 22
        assert data[0]["service"] == "ssh"
        assert data[0]["version"] == "OpenSSH 8.2p1 Ubuntu 4ubuntu0.1"
        assert len(data[0]["cves"]) == 1
        assert data[0]["cves"][0]["id"] == "CVE-2021-1234"
        assert "Test explanation" in data[0]["cves"][0]["gpt_explanation"]
        assert "Test fix" in data[0]["cves"][0]["recommended_fix"]

        # Check port 80 (http)
        assert data[1]["port"] == 80
        assert data[1]["service"] == "http"
        assert data[1]["version"] == "Apache httpd 2.4.46"
        assert len(data[1]["cves"]) == 1
        assert data[1]["cves"][0]["id"] == "CVE-2021-1234" # Same mock CVE for simplicity

        mock_nmap_scanner_class.assert_called_once()
        # NVD called for each service (product, version)
        assert mock_requests_get.call_count == 2
        # OpenAI called for each CVE on each service
        assert mock_openai_create.call_count == 2


@pytest.mark.asyncio
async def test_scan_ip_host_not_found():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class:
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None
        mock_scanner_instance.all_hosts.return_value = [] # Simulate host not found
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post("/api/scan", json={"ip": "1.2.3.4"})

        assert response.status_code == 404
        assert "Host 1.2.3.4 not found or not scannable" in response.json()["detail"]

@pytest.mark.asyncio
async def test_scan_ip_no_open_ports():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class:
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None
        mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
        mock_scanner_instance.__getitem__.return_value = MOCK_NMAP_RESULTS_NO_OPEN_PORTS['127.0.0.1']
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post("/api/scan", json={"ip": "127.0.0.1"})

        assert response.status_code == 200 # The API returns 200 with a message
        # Check for either of the possible messages for no open ports / no services
        response_json = response.json()
        assert ("No open TCP ports found on 127.0.0.1" in response_json.get("message", "") or \
                "No services with version information found on 127.0.0.1" in response_json.get("message", "") or \
                len(response_json) == 0) # If results is an empty list


@pytest.mark.asyncio
async def test_scan_ip_nvd_api_error():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class, \
         patch('main.requests.get') as mock_requests_get:

        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None
        mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
        mock_scanner_instance.__contains__.return_value = True # Ensures 'host in nm' check passes
        mock_scanner_instance.__getitem__.return_value = MOCK_NMAP_RESULTS_SINGLE_HOST_OPEN_PORTS['127.0.0.1']
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        # Simulate NVD API error
        mock_nvd_response = MagicMock()
        # mock_nvd_response.status_code = 500 # Not needed if raise_for_status is mocked
        mock_nvd_response.raise_for_status.side_effect = requests.exceptions.HTTPError("NVD API down")
        mock_requests_get.return_value = mock_nvd_response

        # Patch OPENAI_API_KEY to avoid issues if it's not set in the environment running tests
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key_not_used_here"}), \
             patch('main.OPENAI_API_KEY', "test_key_not_used_here"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post("/api/scan", json={"ip": "127.0.0.1"})

        assert response.status_code == 200 # Main scan succeeds
        data = response.json()
        assert len(data) == 2
        # Check that CVE fetching shows an error
        assert "error" in data[0]["cves"][0]
        assert "Could not fetch CVEs" in data[0]["cves"][0]["error"]

@pytest.mark.asyncio
async def test_scan_ip_openai_api_error():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class, \
         patch('main.requests.get') as mock_requests_get, \
         patch.object(main_openai_client.chat.completions, 'create') as mock_openai_create:

        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None
        mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
        mock_scanner_instance.__contains__.return_value = True # Ensures 'host in nm' check passes
        mock_scanner_instance.__getitem__.return_value = MOCK_NMAP_RESULTS_SINGLE_HOST_OPEN_PORTS['127.0.0.1']
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        mock_nvd_response = MagicMock()
        mock_nvd_response.status_code = 200
        mock_nvd_response.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2021-1234", "descriptions": [{"lang": "en", "value": "Test"}], "metrics": {}, "published": "2021-01-01"}}]}
        mock_requests_get.return_value = mock_nvd_response

        # Simulate OpenAI API error
        mock_openai_create.side_effect = Exception("OpenAI API error")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test_key"}), \
             patch('main.OPENAI_API_KEY', "test_key"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post("/api/scan", json={"ip": "127.0.0.1"})

        assert response.status_code == 200
        data = response.json()
        assert "Error generating explanation via OpenAI" in data[0]["cves"][0]["gpt_explanation"]
        assert "Error generating fix via OpenAI" in data[0]["cves"][0]["recommended_fix"]

@pytest.mark.asyncio
async def test_scan_ip_openai_key_not_configured():
    with patch('main.nmap.PortScanner') as mock_nmap_scanner_class, \
         patch('main.requests.get') as mock_requests_get, \
         patch.object(main_openai_client.chat.completions, 'create') as mock_openai_create:

        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = None
        mock_scanner_instance.all_hosts.return_value = ['127.0.0.1']
        mock_scanner_instance.__contains__.return_value = True # Ensures 'host in nm' check passes
        mock_scanner_instance.__getitem__.return_value = MOCK_NMAP_RESULTS_SINGLE_HOST_OPEN_PORTS['127.0.0.1']
        mock_nmap_scanner_class.return_value = mock_scanner_instance

        mock_nvd_response = MagicMock()
        mock_nvd_response.status_code = 200
        mock_nvd_response.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2021-1234", "descriptions": [{"lang": "en", "value": "Test"}], "metrics": {}, "published": "2021-01-01"}}]}
        mock_requests_get.return_value = mock_nvd_response

        # Ensure OPENAI_API_KEY is the fallback one by patching the global variable in main.py
        with patch('main.OPENAI_API_KEY', "YOUR_OPENAI_API_KEY_FALLBACK"):
            # We also need to ensure the client instance uses this patched key.
            # The simplest way for this test is to assume the global `client` instance in `main.py`
            # is re-evaluated or its `api_key` attribute is affected by the `main.OPENAI_API_KEY` patch.
            # If `main.client` is initialized at import time and doesn't dynamically check `main.OPENAI_API_KEY`
            # per call, this test might need adjustment (e.g. patching `main.client.api_key`).
            # For this test, we assume the `get_gpt_explanation_and_fix` function checks `main.OPENAI_API_KEY` directly.
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post("/api/scan", json={"ip": "127.0.0.1"})

        assert response.status_code == 200
        data = response.json()
        assert "OpenAI API key not configured" in data[0]["cves"][0]["gpt_explanation"]
        assert "OpenAI API key not configured" in data[0]["cves"][0]["recommended_fix"]
        mock_openai_create.assert_not_called()
