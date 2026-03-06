import sys
import json
import requests
from bs4 import BeautifulSoup

def analyze(url):
    results = {
        "python_status": "success",
        "title": "",
        "meta_tags": {},
        "basic_xss_risk": False,
        "suspicious_scripts": []
    }
    
    try:
        # Define a user agent
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecurityExposureAnalyzer/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Grab Title
        if soup.title and soup.title.string:
            results["title"] = soup.title.string.strip()
            
        # 2. Grab Meta Tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                results["meta_tags"][name.lower()] = content
                
        # 3. Simple inline script analysis (Phase 2 Prep)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string: # Inline script
                if 'eval(' in script.string or 'document.write(' in script.string or 'innerHTML' in script.string:
                    results["basic_xss_risk"] = True
            
            src = script.get('src')
            if src and url not in src and not src.startswith('/') and not src.startswith('.'):
                results["suspicious_scripts"].append(src)
                
    except Exception as e:
        results["python_status"] = "error"
        results["error_message"] = str(e)
        
    # Output MUST be pure JSON for Node.js to quickly parse
    print(json.dumps(results))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"python_status": "error", "error_message": "No URL provided"}))
        sys.exit(1)
        
    # Ignore insecure request warnings for basic scanning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    target_url = sys.argv[1]
    analyze(target_url)
