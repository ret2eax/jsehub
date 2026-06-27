# tools/fetch_cisa_browsers.py
# Reuse CISA KEV feed and write per-ecosystem slices for JSC and SpiderMonkey.
# Output:
#   data/jsc_cves.json = { itw_related: [ {cve, dateAdded, vendor, product} ] }
#   data/sm_cves.json  = { itw_related: [ ... ] }
import json, urllib.request, sys, time, ssl, os

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_JSC = "data/jsc_cves.json"
OUT_SM  = "data/sm_cves.json"

# matchers (case-insensitive) for vendor/product strings
JSC_MATCH = ("apple", "webkit", "safari", "javascriptcore")
SM_MATCH  = ("mozilla", "firefox", "gecko", "spidermonkey")

def fetch_json(url):
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(url, context=ctx, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def keep(entry, needles):
    v = f"{entry.get('vendorProject','')} {entry.get('product','')}".lower()
    return any(n in v for n in needles)

def row(r):
    # Capture the descriptive KEV fields the UI uses to derive the vuln Class and show a
    # Description (shortDescription), plus the human-readable name and CWE list.
    return {
        "cve": r.get("cveID"),
        "dateAdded": r.get("dateAdded"),
        "vendor": r.get("vendorProject"),
        "product": r.get("product"),
        "vulnerabilityName": r.get("vulnerabilityName"),
        "shortDescription": r.get("shortDescription"),
        "cwes": r.get("cwes", []),
    }

def main():
    try:
        j = fetch_json(CISA_URL)
        rows = j.get("vulnerabilities", [])
        jsc = [ row(r) for r in rows if keep(r, JSC_MATCH) ]
        sm  = [ row(r) for r in rows if keep(r, SM_MATCH) ]
        os.makedirs("data", exist_ok=True)
        with open(OUT_JSC, "w") as f: json.dump({ "itw_related": jsc }, f, indent=2)
        with open(OUT_SM, "w") as f:  json.dump({ "itw_related": sm  }, f, indent=2)
        print(f"[cisa browsers] wrote {OUT_JSC} ({len(jsc)}) and {OUT_SM} ({len(sm)})")
    except Exception as e:
        os.makedirs("data", exist_ok=True)
        with open(OUT_JSC, "w") as f: json.dump({ "itw_related": [] }, f, indent=2)
        with open(OUT_SM, "w") as f:  json.dump({ "itw_related": [] }, f, indent=2)
        print(f"[cisa browsers] error: {e}; wrote empty lists", file=sys.stderr)

if __name__ == "__main__":
    main()
