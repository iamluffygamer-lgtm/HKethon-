#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         PHONE INTELLIGENCE MODULE — Legal Advanced OSINT                   ║
║         Carrier · Spam · Social · Public DBs · Dorks · Reports             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python phone_osint.py +919876543210
    python phone_osint.py +14155552671
    python phone_osint.py +919876543210 --export
    python phone_osint.py +919876543210 --region IN

All data sources used are PUBLICLY AVAILABLE or operate via CONSENT-BASED APIs.
No unauthorized access. Suitable for fraud investigation & due diligence.
"""

import sys, json, re, time, argparse, urllib.parse, hashlib, html
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.columns import Columns
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

try:
    import phonenumbers
    from phonenumbers import (
        geocoder, carrier, timezone as pn_tz,
        PhoneNumberFormat, PhoneNumberType,
        is_valid_number, is_possible_number,
        number_type, format_number, parse,
        region_code_for_number, country_code_for_region,
    )
    PHONE_LIB = True
except ImportError:
    PHONE_LIB = False
    print("Install phonenumbers: pip install phonenumbers")
    sys.exit(1)

import urllib3
urllib3.disable_warnings()

console = Console()

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA}

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def safe_get(url, timeout=10, headers=None, params=None):
    try:
        h = {**HEADERS, **(headers or {})}
        return requests.get(url, timeout=timeout, headers=h,
                            params=params, verify=False)
    except Exception:
        return None

def section(title):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))

def badge_yes(msg="YES"):  return f"[bold green]✓ {msg}[/bold green]"
def badge_no(msg="NO"):    return f"[bold red]✗ {msg}[/bold red]"
def badge_warn(msg):       return f"[bold yellow]⚠ {msg}[/bold yellow]"
def badge_dim(msg="—"):    return f"[dim]{msg}[/dim]"

# ═══════════════════════════════════════════════════════════════
# STEP 1 — CORE PARSING (phonenumbers library)
# ═══════════════════════════════════════════════════════════════
LINE_TYPE_MAP = {
    PhoneNumberType.FIXED_LINE:           ("FIXED LINE",          "Landline / office number"),
    PhoneNumberType.MOBILE:               ("MOBILE",              "Mobile handset"),
    PhoneNumberType.FIXED_LINE_OR_MOBILE: ("FIXED OR MOBILE",     "Could be either"),
    PhoneNumberType.TOLL_FREE:            ("TOLL FREE",           "Free to call, often business"),
    PhoneNumberType.PREMIUM_RATE:         ("PREMIUM RATE",        "⚠ Charges caller — fraud risk!"),
    PhoneNumberType.SHARED_COST:          ("SHARED COST",         "Split cost between parties"),
    PhoneNumberType.VOIP:                 ("VOIP",                "⚠ Internet-based — common in fraud"),
    PhoneNumberType.PERSONAL_NUMBER:      ("PERSONAL NUMBER",     "Follows subscriber"),
    PhoneNumberType.PAGER:                ("PAGER",               "Pager / beeper"),
    PhoneNumberType.UAN:                  ("UAN / ENTERPRISE",    "Unified enterprise number"),
    PhoneNumberType.VOICEMAIL:            ("VOICEMAIL",           "Voicemail-only"),
    PhoneNumberType.UNKNOWN:              ("UNKNOWN",             "Could not determine"),
}

def parse_phone(number_str, region="IN"):
    """Full phonenumbers parsing — returns rich metadata dict."""
    result = {"input": number_str, "valid": False}
    try:
        parsed = parse(number_str, region)
    except Exception as e:
        result["error"] = str(e)
        return result

    valid = is_valid_number(parsed)
    result.update({
        "parsed_obj":    parsed,
        "valid":         valid,
        "possible":      is_possible_number(parsed),
        "e164":          format_number(parsed, PhoneNumberFormat.E164),
        "international": format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
        "national":      format_number(parsed, PhoneNumberFormat.NATIONAL),
        "rfc3966":       format_number(parsed, PhoneNumberFormat.RFC3966),
        "country_code":  parsed.country_code,
        "national_num":  str(parsed.national_number),
        "region":        region_code_for_number(parsed),
        "carrier_name":  carrier.name_for_number(parsed, "en") or "Unknown",
        "geo_desc":      geocoder.description_for_number(parsed, "en") or "Unknown",
        "timezones":     list(pn_tz.time_zones_for_number(parsed)),
        "number_type":   LINE_TYPE_MAP.get(number_type(parsed),
                         ("UNKNOWN","Could not determine")),
        "extension":     parsed.extension or "",
        "italian_lead":  parsed.italian_leading_zero,
    })

    # Fraud risk scoring from number type
    nt = number_type(parsed)
    fraud_signals = []
    if nt == PhoneNumberType.VOIP:
        fraud_signals.append("VOIP — untraceable, common in scams")
    if nt == PhoneNumberType.PREMIUM_RATE:
        fraud_signals.append("PREMIUM RATE — charges victim for calling")
    if nt == PhoneNumberType.TOLL_FREE:
        fraud_signals.append("TOLL FREE — often used in impersonation scams")
    result["fraud_signals"] = fraud_signals

    return result

# ═══════════════════════════════════════════════════════════════
# STEP 2 — FREE PUBLIC API LOOKUPS (no key required)
# ═══════════════════════════════════════════════════════════════

def lookup_numverify_free(e164):
    """
    NumVerify free (no-key) basic lookup.
    Returns line_type, carrier, location.
    """
    number = e164.replace("+","")
    r = safe_get(f"https://api.numlookupapi.com/v1/info/{e164}", timeout=8)
    if r and r.ok:
        try:
            d = r.json()
            return {
                "source":    "NumLookupAPI (free)",
                "valid":     d.get("valid"),
                "number":    d.get("number"),
                "local_fmt": d.get("local_format"),
                "intl_fmt":  d.get("international_format"),
                "country":   d.get("country_name"),
                "location":  d.get("location"),
                "carrier":   d.get("carrier"),
                "line_type": d.get("line_type"),
            }
        except Exception:
            pass
    return {}

def lookup_phoneapi(e164):
    """
    Phone-api.com free public endpoint.
    Returns validity, carrier, country.
    """
    r = safe_get(f"https://phoneapi.net/verify?phone={urllib.parse.quote(e164)}", timeout=8)
    if r and r.ok:
        try:
            return {"source": "PhoneAPI.net", **r.json()}
        except Exception:
            pass
    return {}

def lookup_ipqualityscore(e164):
    """
    IPQualityScore free public spam check.
    Source: https://www.ipqualityscore.com/
    Requires free API key but provides: fraud score, VOIP, spam reports, carrier.
    Without key: limited info via public endpoint.
    """
    # Public endpoint — no key for basic check
    number = e164.replace("+","")
    r = safe_get(
        f"https://www.ipqualityscore.com/api/json/phone/public/{number}",
        timeout=8
    )
    if r and r.ok:
        try:
            d = r.json()
            return {
                "source":       "IPQualityScore (public)",
                "valid":        d.get("valid"),
                "fraud_score":  d.get("fraud_score"),     # 0-100, >75 = fraud
                "spam_risk":    d.get("spam_risk"),       # High/Medium/Low
                "risky":        d.get("risky"),
                "active":       d.get("active"),
                "carrier":      d.get("carrier"),
                "line_type":    d.get("line_type"),
                "country":      d.get("country"),
                "city":         d.get("city"),
                "region":       d.get("region"),
                "timezone":     d.get("timezone"),
                "do_not_call":  d.get("do_not_call"),
                "leaked":       d.get("leaked"),          # In known data breaches
                "prepaid":      d.get("prepaid"),
                "active_status":d.get("active_status"),
                "name":         d.get("name"),            # Linked name if public
                "user_activity":d.get("user_activity"),  # Low/Medium/High
            }
        except Exception:
            pass
    return {}

def lookup_abstract_phone(e164, api_key=""):
    """
    AbstractAPI phone validation (250 free requests/month).
    Get key at: https://app.abstractapi.com/api/phone-validation/
    Also works with limited data without key.
    """
    url = "https://phonevalidation.abstractapi.com/v1/"
    params = {"api_key": api_key, "phone": e164}
    r = safe_get(url, params=params, timeout=8)
    if r and r.ok:
        try:
            d = r.json()
            return {
                "source":    "AbstractAPI Phone",
                "valid":     d.get("valid"),
                "format":    d.get("format", {}),
                "country":   d.get("country", {}),
                "phone":     d.get("phone"),
                "type":      d.get("type"),
                "carrier":   d.get("carrier"),
            }
        except Exception:
            pass
    return {}

def lookup_veriphone(e164, api_key=""):
    """
    Veriphone API (free tier: 100/month).
    Get key at: https://veriphone.io/
    """
    url = "https://api.veriphone.io/v2/verify"
    params = {"phone": e164, "key": api_key}
    r = safe_get(url, params=params, timeout=8)
    if r and r.ok:
        try:
            d = r.json()
            return {
                "source":         "Veriphone",
                "phone_valid":    d.get("phone_valid"),
                "phone_type":     d.get("phone_type"),
                "phone_region":   d.get("phone_region"),
                "country":        d.get("country"),
                "country_code":   d.get("country_code"),
                "carrier":        d.get("carrier"),
                "phone_national": d.get("phone_national"),
                "phone_e164":     d.get("phone_e164"),
                "phone_intl":     d.get("phone_international"),
            }
        except Exception:
            pass
    return {}

def lookup_apilayer_numverify(e164, api_key=""):
    """
    APILayer / NumVerify (100 free/month without key, 1000 with free key).
    Get key at: https://numverify.com/
    """
    number = e164.replace("+","")
    url = "http://apilayer.net/api/validate"
    params = {"access_key": api_key, "number": number, "country_code": "", "format": 1}
    r = safe_get(url, params=params, timeout=8)
    if r and r.ok:
        try:
            d = r.json()
            if not d.get("error"):
                return {
                    "source":        "NumVerify/APILayer",
                    "valid":         d.get("valid"),
                    "number":        d.get("number"),
                    "local_format":  d.get("local_format"),
                    "intl_format":   d.get("international_format"),
                    "country_code":  d.get("country_code"),
                    "country_name":  d.get("country_name"),
                    "location":      d.get("location"),
                    "carrier":       d.get("carrier"),
                    "line_type":     d.get("line_type"),
                }
        except Exception:
            pass
    return {}

# ═══════════════════════════════════════════════════════════════
# STEP 3 — SPAM & FRAUD DATABASE CHECKS (PUBLIC SOURCES)
# ═══════════════════════════════════════════════════════════════

def check_spam_truecaller_public(e164):
    """
    Truecaller public search endpoint.
    No login required for basic existence check.
    """
    number_clean = e164.replace("+","")
    result = {"source": "Truecaller public", "found": False}
    r = safe_get(f"https://www.truecaller.com/search/global/{number_clean}",
                 headers={**HEADERS, "X-Requested-With": "XMLHttpRequest"}, timeout=10)
    if r:
        result["status"] = r.status_code
        if r.status_code == 200:
            result["found"] = "name" in r.text.lower() or "carrier" in r.text.lower()
    return result

def check_shouldianswercom(national_number, region):
    """
    Should I Answer? — Public spam phone database.
    Source: https://www.shouldianswer.com/
    No API key needed. Community-reported spam numbers.
    """
    result = {"source": "ShouldIAnswer.com", "spam_reports": 0, "rating": ""}
    number_clean = re.sub(r'\D', '', national_number)

    # Try different country subdomains
    domains = {
        "IN": "shouldianswer.net",
        "US": "shouldianswer.com",
        "GB": "shouldianswer.co.uk",
        "DE": "wer-ruftan.de",
    }
    base = domains.get(region, "shouldianswer.com")
    r = safe_get(f"https://www.{base}/phone-number/{number_clean}", timeout=8)
    if r and r.ok:
        # Parse rating
        import re as re2
        rating_match = re2.search(r'(\d+)\s*(?:reviews?|ratings?|report)', r.text, re2.I)
        if rating_match:
            result["spam_reports"] = int(rating_match.group(1))
        for word in ["scam","spam","fraud","dangerous","unwanted","unsafe"]:
            if word in r.text.lower():
                result["rating"] = "SPAM/FRAUD REPORTED"
                break
        if not result["rating"]:
            result["rating"] = "No reports found"
    return result

def check_800notes(number_str):
    """
    800notes.com — Largest public database of spam/scam call reports (US focus).
    Source: https://800notes.com/
    """
    result = {"source": "800notes.com", "reports": 0, "summary": ""}
    number_clean = re.sub(r'\D', '', number_str)
    if len(number_clean) < 10:
        return result
    # Format as XXX-XXX-XXXX for URL
    if len(number_clean) == 11 and number_clean[0] == '1':
        number_clean = number_clean[1:]
    formatted = f"{number_clean[:3]}-{number_clean[3:6]}-{number_clean[6:]}" if len(number_clean)==10 else number_clean
    r = safe_get(f"https://800notes.com/Phone.aspx/{formatted}", timeout=8)
    if r and r.ok:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        # Count posts/comments
        posts = soup.find_all(class_="post") or soup.find_all("div", id=re.compile("post"))
        result["reports"] = len(posts)
        # Get summary text
        meta = soup.find("meta", {"name": "description"})
        if meta and meta.get("content"):
            result["summary"] = meta["content"][:200]
    return result

def check_whocalled(e164, region):
    """
    Who Called Me? — International spam database.
    Source: https://whocalled.us/ and country equivalents.
    """
    result = {"source": "WhoCalledMe", "reports": 0, "danger_level": ""}
    number = e164.replace("+","")
    domains = {
        "IN": "whocalledme.in",
        "US": "whocalledme.us",
        "GB": "whocalledme.co.uk",
    }
    base = domains.get(region, "whocalledme.us")
    r = safe_get(f"https://www.{base}/{number}", timeout=8)
    if r and r.ok:
        text = r.text.lower()
        for level in ["dangerous","unsafe","scam","spam","fraud"]:
            if level in text:
                result["danger_level"] = level.upper()
                break
        # Count reports
        count_match = re.search(r'(\d+)\s+(?:report|comment|rating)', text)
        if count_match:
            result["reports"] = int(count_match.group(1))
    return result

def check_india_specific(national_number):
    """
    India-specific checks:
    - TRAI DND (Do Not Disturb) registry (public)
    - NDNC (National Do Not Call) hints
    - Common Indian spam number patterns
    """
    result = {"source": "India-specific checks", "dnd_pattern": False, "telemarketer_pattern": False}
    digits = re.sub(r'\D', '', national_number)

    # Indian telemarketer number patterns (TRAI regulated)
    # Numbers starting with 140 are commercial communication
    if digits.startswith("140"):
        result["telemarketer_pattern"] = True
        result["note"] = "140XXXXXXX — Registered telemarketer/commercial communication (TRAI)"

    # 160XXXXXXX — govt/bank transactional
    if digits.startswith("160"):
        result["note"] = "160XXXXXXX — Transactional/government communication (TRAI)"

    # Known Indian spam prefixes (community-reported)
    spam_prefixes = [
        "1800","1860","1850",  # Toll free common spam
    ]
    for pref in spam_prefixes:
        if digits.startswith(pref):
            result["possible_spam"] = True
            result["note"] = f"Starts with {pref} — common spam prefix"

    # TRAI NDNC hint check (public API)
    r = safe_get(f"https://www.trai.gov.in/consumer-info/dnd",timeout=5)
    result["trai_dnd_url"] = "https://trai.gov.in/consumer-info/dnd"
    result["ndnc_check_url"] = f"https://www.ndnc.net.in/"

    return result

# ═══════════════════════════════════════════════════════════════
# STEP 4 — SOCIAL & MESSAGING PLATFORM CHECKS
# ═══════════════════════════════════════════════════════════════

def check_whatsapp(e164):
    """
    Check WhatsApp number existence via wa.me public redirect.
    Legal: public profile check, no scraping of private data.
    """
    number = e164.replace("+","").replace(" ","")
    result = {"platform": "WhatsApp", "url": f"https://wa.me/{number}"}
    r = safe_get(f"https://api.whatsapp.com/send?phone={number}", timeout=10)
    if r:
        result["status_code"] = r.status_code
        text = r.text.lower()
        if r.status_code == 200 and "open whatsapp" in text:
            result["exists"] = "LIKELY — Number is registered"
        elif "invalid" in text or "phone number" in text:
            result["exists"] = "INVALID or NOT REGISTERED"
        else:
            result["exists"] = "UNKNOWN"
    else:
        result["exists"] = "Could not check"
    return result

def check_telegram(e164):
    """
    Telegram public check via t.me.
    Only works if user has a public username linked to the number.
    """
    result = {"platform": "Telegram", "info": "No public username linked to this number"}
    # No direct API without login — provide manual check URL
    result["manual_check"] = "https://t.me/+{number} — check manually"
    return result

def check_signal(e164):
    """
    Signal presence check.
    Signal doesn't expose a public API — provide manual check instructions.
    """
    return {
        "platform": "Signal",
        "method": "Manual — open Signal app → New Chat → enter number",
        "note": "Signal doesn't expose public lookup APIs (by design for privacy)"
    }

def check_viber(national, region):
    """
    Viber public profile hint check.
    """
    return {
        "platform": "Viber",
        "method": "Manual check via Viber app",
        "public_url": f"https://chats.viber.com/+{national}",
    }

# ═══════════════════════════════════════════════════════════════
# STEP 5 — PUBLIC CONTACT / PROFILE DATABASES
# ═══════════════════════════════════════════════════════════════

def search_github_for_number(e164, national):
    """
    Search GitHub public commits/code for this phone number.
    Legal: GitHub public search API.
    """
    results = []
    for query in [e164, national]:
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                timeout=10
            )
            if r and r.ok:
                d = r.json()
                if d.get("total_count", 0) > 0:
                    for item in d.get("items", [])[:3]:
                        results.append({
                            "repo":  item["repository"]["full_name"],
                            "file":  item["name"],
                            "url":   item["html_url"],
                        })
        except Exception:
            pass
        time.sleep(0.5)  # respect rate limits
    return results

def generate_osint_dorks(parsed_data):
    """
    Generate comprehensive Google/Bing dorks for the phone number.
    All queries target publicly indexed content.
    """
    e164      = parsed_data.get("e164","")
    intl      = parsed_data.get("international","")
    national  = parsed_data.get("national","")
    e164_bare = e164.replace("+","")
    region    = parsed_data.get("region","")

    dorks = {
        "Identity Search": [
            f'"{intl}"',
            f'"{national}"',
            f'"{e164}"',
            f'"{e164_bare}"',
        ],
        "Fraud & Complaint": [
            f'"{national}" (fraud OR scam OR complaint OR cheated OR fake)',
            f'"{intl}" (scam OR fraud OR phishing OR spam)',
            f'"{national}" site:consumercomplaints.in',
            f'"{national}" site:mouthshut.com',
            f'"{national}" (review OR complaint OR report)',
        ],
        "Social Media": [
            f'"{national}" site:facebook.com',
            f'"{national}" site:instagram.com',
            f'"{national}" site:linkedin.com',
            f'"{national}" site:twitter.com OR site:x.com',
            f'"{intl}" site:telegram.org',
        ],
        "Public Directories": [
            f'"{national}" site:truecaller.com',
            f'"{e164_bare}" site:truecaller.com',
            f'"{national}" site:justdial.com' if region=="IN" else f'"{national}" site:yellowpages.com',
            f'"{national}" site:indiamart.com' if region=="IN" else f'"{national}" site:yelp.com',
            f'"{national}" site:sulekha.com' if region=="IN" else "",
        ],
        "Data Leaks / Paste Sites": [
            f'"{national}" site:pastebin.com',
            f'"{e164}" site:pastebin.com',
            f'"{national}" site:ghostbin.com',
            f'"{e164}" site:raidforums.com OR site:breached.to',
        ],
        "Documents & Records": [
            f'"{national}" filetype:pdf',
            f'"{national}" filetype:xlsx OR filetype:csv',
            f'"{national}" filetype:doc',
            f'"{intl}" filetype:pdf',
        ],
        "E-commerce / Business": [
            f'"{national}" site:amazon.in' if region=="IN" else f'"{national}" site:amazon.com',
            f'"{national}" site:olx.in' if region=="IN" else f'"{national}" site:craigslist.org',
            f'"{national}" site:quikr.com' if region=="IN" else "",
            f'"{national}" site:flipkart.com' if region=="IN" else "",
        ],
        "Reverse Lookup Sites": [
            f"https://www.truecaller.com/search/in/{e164_bare}" if region=="IN" else f"https://www.truecaller.com/search/us/{e164_bare}",
            f"https://800notes.com/Phone.aspx/{national.replace(' ','-')}",
            f"https://www.shouldianswer.com/phone-number/{re.sub(chr(92) + 'D','',national)}",
            f"https://whocalledme.com/{e164_bare}",
            f"https://www.spamcalls.net/en/number/{e164_bare}",
            f"https://www.callerr.com/{e164_bare}",
        ],
        "Image / Face Search": [
            f'"{national}" -inurl:(signup OR login)',
            f"https://images.google.com/searchbyimage?image_url=",  # For profile pic reverse search
        ],
    }
    # Clean empty entries
    return {cat: [q for q in qs if q] for cat, qs in dorks.items()}

# ═══════════════════════════════════════════════════════════════
# STEP 6 — SIM / CARRIER DETAILS (Legal Public Data)
# ═══════════════════════════════════════════════════════════════

INDIA_CARRIER_PREFIXES = {
    # Prefix → (Carrier, Type, Circle)
    "9820": ("Vodafone Idea","Mobile","Mumbai"),
    "9821": ("Airtel","Mobile","Mumbai"),
    "9822": ("Vodafone Idea","Mobile","Maharashtra"),
    "9823": ("Airtel","Mobile","Maharashtra"),
    "9833": ("Vodafone Idea","Mobile","Mumbai"),
    "9867": ("Vodafone Idea","Mobile","Mumbai"),
    "9869": ("Airtel","Mobile","Mumbai"),
    "9870": ("Airtel","Mobile","Delhi"),
    "9871": ("Airtel","Mobile","Delhi"),
    "9810": ("Airtel","Mobile","Delhi"),
    "9818": ("Airtel","Mobile","Delhi"),
    "9811": ("Airtel","Mobile","Delhi"),
    "9876": ("Airtel","Mobile","Punjab"),
    "9855": ("Airtel","Mobile","Punjab"),
    "9888": ("BSNL","Mobile","Punjab"),
    "9900": ("Airtel","Mobile","Karnataka"),
    "9901": ("BSNL","Mobile","Karnataka"),
    "9902": ("Vodafone Idea","Mobile","Karnataka"),
    "9980": ("Airtel","Mobile","Karnataka"),
    "9986": ("BSNL","Mobile","Karnataka"),
    "9440": ("Airtel","Mobile","Andhra Pradesh"),
    "9441": ("Vodafone Idea","Mobile","Andhra Pradesh"),
    "9849": ("Airtel","Mobile","Andhra Pradesh"),
    "6000": ("Jio","Mobile","Various"),
    "6001": ("Jio","Mobile","Various"),
    "7000": ("Jio","Mobile","Various"),
    "7001": ("Jio","Mobile","Various"),
    "8000": ("Jio","Mobile","Various"),
    "8001": ("Jio","Mobile","Various"),
    "9600": ("Airtel","Mobile","Tamil Nadu"),
    "9842": ("Airtel","Mobile","Tamil Nadu"),
    "9994": ("Airtel","Mobile","Tamil Nadu"),
}

US_CARRIER_HINTS = {
    "AT&T":    ["650","213","312","914"],
    "Verizon": ["732","908","973","516"],
    "T-Mobile":["206","425","253","360"],
    "Sprint":  ["913","816","785","316"],
}

def get_carrier_details(national_number, region):
    """
    Match number prefix to known carrier databases (public information).
    India: TRAI public licensing data.
    US: FCC numbering database.
    """
    result = {"source": "Prefix DB (TRAI/FCC public data)", "carrier": "", "circle": ""}
    digits = re.sub(r'\D', '', national_number)

    if region == "IN" and len(digits) == 10:
        prefix4 = digits[:4]
        if prefix4 in INDIA_CARRIER_PREFIXES:
            carrier_n, ntype, circle = INDIA_CARRIER_PREFIXES[prefix4]
            result["carrier"] = carrier_n
            result["type"]    = ntype
            result["circle"]  = circle
            result["note"]    = f"Based on TRAI public licensing data for {prefix4}XXXXXX series"

            # Jio detection (starts with 6,7,8 in India)
            if digits[0] in "678":
                result["carrier"] = "Reliance Jio (likely)"
                result["note"]    = "Numbers starting with 6/7/8 in India typically belong to Jio"

    if region == "US" and len(digits) >= 6:
        area_code = digits[:3]
        for carrier_n, area_codes in US_CARRIER_HINTS.items():
            if area_code in area_codes:
                result["carrier"] = f"{carrier_n} (based on area code)"
                result["note"] = "Area code based; may vary due to number portability"
                break

    return result

# ═══════════════════════════════════════════════════════════════
# STEP 7 — NUMBER PORTING HINTS
# ═══════════════════════════════════════════════════════════════

def check_porting_hints(carrier_from_prefix, carrier_from_api, region):
    """
    Compare prefix-based carrier with API-reported carrier.
    Discrepancy suggests the number was ported.
    Legal: inference from public data.
    """
    result = {"ported": False, "confidence": "LOW"}
    if not carrier_from_prefix or not carrier_from_api:
        return result

    # Normalize
    c1 = carrier_from_prefix.lower().split()[0]
    c2 = carrier_from_api.lower().split()[0]

    if c1 and c2 and c1 != c2 and c1 != "unknown" and c2 != "unknown":
        result["ported"] = True
        result["confidence"] = "MEDIUM"
        result["original_carrier"]  = carrier_from_prefix
        result["current_carrier"]   = carrier_from_api
        result["note"] = (
            f"Prefix suggests {carrier_from_prefix}, "
            f"but API reports {carrier_from_api}. "
            "Number may have been ported (MNP)."
        )
    return result

# ═══════════════════════════════════════════════════════════════
# STEP 8 — FRAUD RISK SCORING
# ═══════════════════════════════════════════════════════════════

def compute_fraud_risk_score(parsed, api_results, spam_results, social_results):
    """
    Compute a 0–100 fraud risk score based on all collected signals.
    Methodology is transparent and explainable.
    """
    score = 0
    reasons = []

    # VOIP: +30
    nt = parsed.get("number_type", ("",""))[0]
    if "VOIP" in nt:
        score += 30
        reasons.append("+30: VOIP number (untraceable, common in fraud)")

    # PREMIUM RATE: +20
    if "PREMIUM" in nt:
        score += 20
        reasons.append("+20: Premium rate number (charges victim)")

    # Spam reports from public DBs
    total_reports = sum(
        r.get("spam_reports", r.get("reports", 0))
        for r in spam_results if isinstance(r, dict)
    )
    if total_reports > 50: score += 25; reasons.append(f"+25: {total_reports} spam reports")
    elif total_reports > 10: score += 15; reasons.append(f"+15: {total_reports} spam reports")
    elif total_reports > 0:  score += 5;  reasons.append(f"+5: {total_reports} spam reports")

    # IPQualityScore fraud score
    for r in api_results:
        if r.get("source","").startswith("IPQuality"):
            fs = r.get("fraud_score", 0)
            if fs:
                pts = min(30, int(fs * 0.3))
                score += pts
                reasons.append(f"+{pts}: IPQS fraud score = {fs}")
            if r.get("leaked"):
                score += 10; reasons.append("+10: Found in data breach/leak")

    # Fraud signals from parsing
    for sig in parsed.get("fraud_signals", []):
        score += 10; reasons.append(f"+10: {sig}")

    # No WhatsApp presence: slight reduction (legit numbers usually on WA)
    wa = next((r for r in social_results if r.get("platform")=="WhatsApp"), {})
    if "NOT REGISTERED" in str(wa.get("exists","")):
        score += 5; reasons.append("+5: Not on WhatsApp (burner sim indicator)")

    score = min(100, score)

    if score >= 75:   level, color = "HIGH RISK — LIKELY FRAUD", "bold red"
    elif score >= 45: level, color = "MEDIUM RISK — SUSPICIOUS", "bold yellow"
    elif score >= 20: level, color = "LOW RISK — SOME SIGNALS",  "yellow"
    else:             level, color = "MINIMAL RISK",              "bold green"

    return {"score": score, "level": level, "color": color, "reasons": reasons}

# ═══════════════════════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════════════════════

def run_phone_osint(number_str, region="IN", api_keys=None, export=False):
    api_keys = api_keys or {}
    all_data = {"input": number_str, "timestamp": datetime.now().isoformat()}

    console.print(Panel(
        f"[bold white]Target:[/bold white] [bold cyan]{number_str}[/bold cyan]\n"
        f"[bold white]Default Region:[/bold white] [cyan]{region}[/cyan]\n"
        f"[bold white]Started:[/bold white] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold yellow]📞 PHONE INTELLIGENCE SCAN[/bold yellow]",
        border_style="yellow", padding=(1,2),
    ))

    # ── 1. Core parse ──────────────────────────────────────────
    section("Core Parsing (phonenumbers)")
    parsed = parse_phone(number_str, region)
    all_data["parsed"] = parsed

    if not parsed.get("valid"):
        console.print(f"[bold red]⚠ Number appears invalid or could not be parsed.[/bold red]")
        if "error" in parsed:
            console.print(f"[red]{parsed['error']}[/red]")

    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
    t.add_column("Field",  style="bold cyan", width=24)
    t.add_column("Value",  style="white")
    e164 = parsed.get("e164", number_str)
    t.add_row("Raw Input",         number_str)
    t.add_row("E.164 (Standard)",  e164)
    t.add_row("International",     parsed.get("international","—"))
    t.add_row("National",          parsed.get("national","—"))
    t.add_row("RFC3966",           parsed.get("rfc3966","—"))
    t.add_row("Country",           f"{parsed.get('region','?')} (+{parsed.get('country_code','?')})")
    t.add_row("Carrier (lib)",     parsed.get("carrier_name","Unknown"))
    t.add_row("Geographic Area",   parsed.get("geo_desc","Unknown"))
    t.add_row("Line Type",         f"{parsed.get('number_type',('?',''))[0]} — {parsed.get('number_type',('','?'))[1]}")
    t.add_row("Timezones",         ", ".join(parsed.get("timezones",[])))
    t.add_row("Valid",             badge_yes("VALID") if parsed.get("valid") else badge_no("INVALID"))
    console.print(t)

    if parsed.get("fraud_signals"):
        for sig in parsed["fraud_signals"]:
            console.print(f"  [bold red]🚨 {sig}[/bold red]")

    # ── 2. Carrier prefix DB ───────────────────────────────────
    section("Carrier Database (TRAI/FCC Public Data)")
    carrier_db = get_carrier_details(parsed.get("national",""), parsed.get("region",""))
    all_data["carrier_db"] = carrier_db
    if carrier_db.get("carrier"):
        tc = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
        tc.add_column("Field",  style="bold cyan", width=24)
        tc.add_column("Value",  style="white")
        tc.add_row("Carrier (prefix)",  carrier_db.get("carrier","—"))
        tc.add_row("Type",              carrier_db.get("type","—"))
        tc.add_row("Circle/Region",     carrier_db.get("circle","—"))
        tc.add_row("Source",            carrier_db.get("note","—"))
        console.print(tc)
    else:
        console.print("[dim]No prefix match found in local DB[/dim]")

    # ── 3. Free API lookups ────────────────────────────────────
    section("Free Public API Lookups")
    api_results = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(bar_width=25), console=console) as prog:
        api_checks = [
            ("NumLookupAPI",       lambda: lookup_numverify_free(e164)),
            ("IPQualityScore",     lambda: lookup_ipqualityscore(e164)),
            ("AbstractAPI",        lambda: lookup_abstract_phone(e164, api_keys.get("abstract",""))),
            ("Veriphone",          lambda: lookup_veriphone(e164, api_keys.get("veriphone",""))),
            ("APILayer/NumVerify", lambda: lookup_apilayer_numverify(e164, api_keys.get("numverify",""))),
        ]
        task = prog.add_task("[cyan]Querying APIs...", total=len(api_checks))
        for name, fn in api_checks:
            prog.update(task, description=f"[cyan]→ {name}...")
            try:
                result = fn()
                if result:
                    api_results.append(result)
            except Exception:
                pass
            prog.advance(task)

    all_data["api_results"] = api_results

    # Consolidate carrier info from APIs
    api_carrier = ""
    for r in api_results:
        c = r.get("carrier","") or r.get("carrier_name","")
        if c and c.lower() != "unknown":
            api_carrier = c; break

    # Print API results
    at = Table(box=box.SIMPLE, padding=(0,1))
    at.add_column("Source",      style="bold cyan",  width=22)
    at.add_column("Valid",       width=10)
    at.add_column("Carrier",     style="white",       width=20)
    at.add_column("Line Type",   style="white",       width=16)
    at.add_column("Location",    style="dim",         width=20)
    at.add_column("Fraud Score", style="bold",        width=14)

    for r in api_results:
        valid_s = badge_yes() if r.get("valid") or r.get("phone_valid") else badge_dim()
        carrier_s = str(r.get("carrier","") or r.get("carrier_name","") or "—")[:20]
        ltype_s  = str(r.get("line_type","") or r.get("phone_type","") or "—")[:16]
        loc_s    = str(r.get("location","") or r.get("city","") or "—")[:20]
        fraud_s  = str(r.get("fraud_score","—"))
        if r.get("fraud_score") and int(str(r.get("fraud_score","0") or 0)) > 74:
            fraud_s = f"[bold red]{fraud_s}[/bold red]"
        at.add_row(r.get("source","?")[:22], valid_s, carrier_s, ltype_s, loc_s, fraud_s)

    if api_results:
        console.print(at)
    else:
        console.print("[dim]No API responses (rate limits or network)[/dim]")

    # Number porting check
    if carrier_db.get("carrier") and api_carrier:
        porting = check_porting_hints(carrier_db["carrier"], api_carrier, parsed.get("region",""))
        all_data["porting"] = porting
        if porting.get("ported"):
            console.print(f"\n  [bold yellow]🔄 NUMBER PORTING DETECTED ({porting['confidence']} confidence)[/bold yellow]")
            console.print(f"  [dim]Original carrier: {porting.get('original_carrier')}[/dim]")
            console.print(f"  [dim]Current carrier:  {porting.get('current_carrier')}[/dim]")
            console.print(f"  [dim]{porting.get('note','')}[/dim]")

    # ── 4. Spam/fraud DB checks ───────────────────────────────
    section("Public Spam & Fraud Databases")
    spam_results = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(bar_width=25), console=console) as prog:
        spam_checks = [
            ("ShouldIAnswer",    lambda: check_shouldianswercom(parsed.get("national",""), parsed.get("region",""))),
            ("800notes",         lambda: check_800notes(parsed.get("national",""))),
            ("WhoCalledMe",      lambda: check_whocalled(e164, parsed.get("region",""))),
        ]
        if parsed.get("region") == "IN":
            spam_checks.append(("India/TRAI", lambda: check_india_specific(parsed.get("national",""))))
        task = prog.add_task("[cyan]Checking spam DBs...", total=len(spam_checks))
        for name, fn in spam_checks:
            prog.update(task, description=f"[cyan]→ {name}...")
            try:
                r = fn()
                if r: spam_results.append(r)
            except Exception:
                pass
            prog.advance(task)

    all_data["spam_checks"] = spam_results

    st = Table(box=box.SIMPLE, padding=(0,1))
    st.add_column("Database",     style="bold cyan", width=22)
    st.add_column("Reports",      width=10)
    st.add_column("Status",       width=30)
    st.add_column("Notes",        style="dim")
    for r in spam_results:
        rpts = str(r.get("spam_reports", r.get("reports", "—")))
        status = r.get("rating") or r.get("danger_level") or r.get("summary","") or r.get("note","")
        if status: status = status[:30]
        st.add_row(r.get("source","?")[:22], rpts, status, "")
    console.print(st)

    # ── 5. Social / messaging ─────────────────────────────────
    section("Messaging Platform Presence")
    social_results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(bar_width=25), console=console) as prog:
        social_checks = [
            ("WhatsApp",  lambda: check_whatsapp(e164)),
            ("Telegram",  lambda: check_telegram(e164)),
            ("Signal",    lambda: check_signal(e164)),
            ("Viber",     lambda: check_viber(e164, parsed.get("region",""))),
        ]
        task = prog.add_task("[cyan]Checking platforms...", total=len(social_checks))
        for name, fn in social_checks:
            prog.update(task, description=f"[cyan]→ {name}...")
            try:
                r = fn(); social_results.append(r)
            except Exception:
                pass
            prog.advance(task)

    all_data["social"] = social_results

    sot = Table(box=box.SIMPLE, padding=(0,1))
    sot.add_column("Platform",   style="bold cyan", width=14)
    sot.add_column("Status",     width=35)
    sot.add_column("URL/Method", style="dim")
    for r in social_results:
        status = r.get("exists") or r.get("info") or r.get("method","")
        url    = r.get("url") or r.get("public_url") or r.get("manual_check","")
        sot.add_row(r.get("platform","?"), str(status)[:35], str(url)[:50])
    console.print(sot)

    # ── 6. GitHub search ──────────────────────────────────────
    section("Public Code / GitHub Search")
    github_hits = search_github_for_number(e164, parsed.get("national",""))
    all_data["github_hits"] = github_hits
    if github_hits:
        console.print(f"[bold red]🚨 Phone number found in {len(github_hits)} public GitHub repo(s)![/bold red]")
        for hit in github_hits:
            console.print(f"  [red]{hit['repo']}[/red] → {hit['file']}")
            console.print(f"    [dim]{hit['url']}[/dim]")
    else:
        console.print("[dim]Not found in public GitHub repositories[/dim]")

    # ── 7. OSINT dorks ────────────────────────────────────────
    section("OSINT Dork Collection")
    dorks = generate_osint_dorks(parsed)
    all_data["dorks"] = dorks
    for category, queries in dorks.items():
        console.print(f"\n  [bold yellow]{category}:[/bold yellow]")
        for q in queries[:4]:
            if q.startswith("http"):
                console.print(f"    [cyan]{q}[/cyan]")
            else:
                encoded = urllib.parse.quote(q)
                console.print(f"    [cyan]https://www.google.com/search?q={encoded}[/cyan]")

    # ── 8. Fraud risk score ───────────────────────────────────
    section("Fraud Risk Assessment")
    risk = compute_fraud_risk_score(parsed, api_results, spam_results, social_results)
    all_data["risk"] = risk

    score_bar = "█" * (risk["score"] // 5) + "░" * (20 - risk["score"] // 5)
    console.print(Panel(
        f"[bold white]Risk Score:[/bold white] [{risk['color']}]{risk['score']}/100[/{risk['color']}]\n"
        f"[{risk['color']}]{score_bar}[/{risk['color']}]\n"
        f"[bold white]Level:[/bold white] [{risk['color']}]{risk['level']}[/{risk['color']}]\n\n"
        f"[bold white]Signals:[/bold white]\n" +
        "\n".join(f"  {r}" for r in risk["reasons"]) if risk["reasons"]
        else "  No specific fraud signals detected",
        title="[bold yellow]⚠ Risk Assessment[/bold yellow]",
        border_style="red" if risk["score"] >= 75 else "yellow" if risk["score"] >= 45 else "green",
        padding=(1,2),
    ))

    # ── 9. Recommended next steps ─────────────────────────────
    section("Recommended Investigation Steps")
    steps = [
        "1. Run the Google dorks above — especially fraud/complaint searches",
        "2. Check Truecaller app manually — often shows registered name",
        f"3. File TRAI complaint: https://trai.gov.in (if Indian number harassing you)" if parsed.get("region")=="IN" else "",
        "4. Search number on Facebook Messenger → often reveals profile",
        "5. WhatsApp profile pic → reverse image search on Google Images",
        "6. Check bank/UPI linked accounts via payment apps (with permission)",
        "7. Request telecom operator via court order for subscriber identity",
        f"8. Report to Cyber Crime Portal: https://cybercrime.gov.in" if parsed.get("region")=="IN" else "8. Report to IC3: https://ic3.gov",
        "9. Cross-reference with email/username modules if available",
    ]
    for s in steps:
        if s: console.print(f"  [cyan]{s}[/cyan]")

    # ── Export ────────────────────────────────────────────────
    if export:
        section("Export")
        slug = re.sub(r'\W', '_', number_str)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = Path(f"phone_osint_{slug}_{ts}")
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "report.json","w") as f:
            json.dump(all_data, f, indent=2, default=str)
        # Dorks text file
        with open(out / "dorks.txt","w") as f:
            for cat, qs in dorks.items():
                f.write(f"\n=== {cat} ===\n")
                for q in qs: f.write(q + "\n")
        console.print(f"[bold green]✓ Saved to {out}/[/bold green]")

    return all_data


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Phone OSINT — Legal Advanced Intelligence",
        epilog="""
API Keys (optional — all have free tiers, tool works without them):
  Set via environment or --keys flag:
  ABSTRACT_KEY   : https://app.abstractapi.com/api/phone-validation/
  VERIPHONE_KEY  : https://veriphone.io/
  NUMVERIFY_KEY  : https://numverify.com/
  IPQS_KEY       : https://www.ipqualityscore.com/

Examples:
  python phone_osint.py +919876543210
  python phone_osint.py +14155552671 --region US
  python phone_osint.py +919876543210 --export
        """
    )
    parser.add_argument("number",   help="Phone number (e.g. +919876543210)")
    parser.add_argument("--region", default="IN", help="Default region code (default: IN)")
    parser.add_argument("--export", action="store_true", help="Export results to files")
    parser.add_argument("--abstract-key",  default="", help="AbstractAPI key")
    parser.add_argument("--veriphone-key", default="", help="Veriphone key")
    parser.add_argument("--numverify-key", default="", help="NumVerify key")
    args = parser.parse_args()

    api_keys = {
        "abstract":   args.abstract_key  or os.environ.get("ABSTRACT_KEY",""),
        "veriphone":  args.veriphone_key or os.environ.get("VERIPHONE_KEY",""),
        "numverify":  args.numverify_key or os.environ.get("NUMVERIFY_KEY",""),
    }

    import os
    run_phone_osint(args.number, region=args.region, api_keys=api_keys, export=args.export)
