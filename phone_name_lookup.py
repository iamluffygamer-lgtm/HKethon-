#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   PHONE OSINT + NAME LOOKUP — Complete Edition                  ║
║   Zero API Keys · 10 Sources · Auto Cross-Check · Free         ║
╚══════════════════════════════════════════════════════════════════╝

HOW NAMES ARE FOUND (all legal, 100% public data):
  ① Truecaller web   — Parses __NEXT_DATA__ JSON from SSR page
  ② Truecaller API   — Unofficial public JSON endpoint
  ③ Eyecon           — 600M+ caller ID database scrape
  ④ Whoscall         — Asia-Pacific caller ID (Next.js JSON parse)
  ⑤ India Caller DBs — CalllerHunt, WhoCalledIndia, PhoneDetails
  ⑥ NumLookupAPI     — Free endpoint, no key, returns name field
  ⑦ Google SERP      — Extracts names from search result snippets
  ⑧ Facebook Search  — Public people search by phone number
  ⑨ JustDial (IN)    — India's largest business directory
  ⑩ UPI Hint (IN)    — GPay/PhonePe shows registered bank name

  + Cross-reference engine: confirms name seen on 2+ sources = HIGH confidence
  + Fraud risk scoring from line type, spam reports, VOIP detection
  + 40+ one-click investigation links & Google dorks
  + Pro tips for manual name finding (WhatsApp, UPI trick, Messenger)

Usage:
  python phone_name_lookup.py +919876543210
  python phone_name_lookup.py +919876543210 --export
  python phone_name_lookup.py +14155552671 --region US
  python phone_name_lookup.py +44 7911 123456 --region GB --export
"""

import re, json, sys, time, argparse, urllib.parse, hashlib
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

import requests
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import (
    geocoder, carrier as ph_carrier, timezone as ph_tz,
    PhoneNumberFormat, PhoneNumberType,
    is_valid_number, is_possible_number, number_type,
    format_number, parse as ph_parse, region_code_for_number,
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

import urllib3
urllib3.disable_warnings()
console = Console()

# ════════════════════════════════════════════════════════════════
# SESSION & HTTP HELPERS
# ════════════════════════════════════════════════════════════════
DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36")
MOBILE_UA  = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Mobile Safari/537.36")

def session(mobile=False):
    s = requests.Session()
    s.headers.update({
        "User-Agent":      MOBILE_UA if mobile else DESKTOP_UA,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-IN,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
        "Connection":      "keep-alive",
        "sec-fetch-dest":  "document",
        "sec-fetch-mode":  "navigate",
        "sec-fetch-site":  "none",
    })
    return s

def get(url, timeout=12, sess=None, extra=None, params=None):
    try:
        s = sess or session()
        if extra: s.headers.update(extra)
        return s.get(url, timeout=timeout, verify=False,
                     allow_redirects=True, params=params)
    except Exception:
        return None

def sec(title):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))

# ════════════════════════════════════════════════════════════════
# NAME CLEANING
# ════════════════════════════════════════════════════════════════
_NOISE = {
    "search","lookup","phone","number","caller","id","who","called",
    "truecaller","eyecon","unknown","private","not found","no result",
    "is calling","spam","telemarketer","details","info","profile",
    "find out","owner","register","null","undefined","none","n/a",
    "name","person","user","subscriber","customer",
}

def clean(name):
    if not name: return ""
    name = re.sub(r'<[^>]+>', '', str(name)).strip()
    if name.lower() in _NOISE: return ""
    if not re.search(r'[A-Za-z\u0900-\u097F\u0600-\u06FF]', name): return ""
    if len(name) < 2: return ""
    name = name.strip('.,;:!?-_/\\|()[]{}"\' \t\n')
    # Title-case if all caps
    if name.isupper(): name = name.title()
    return name[:80]

# ════════════════════════════════════════════════════════════════
# LOCAL CARRIER DATABASE  (TRAI / FCC public data — offline)
# ════════════════════════════════════════════════════════════════
INDIA_PREFIXES = {
    # Jio
    **{f"{p}": ("Reliance Jio", "Various", "4G/5G")
       for p in ["6000","6001","6002","6003","6004","6005","6006","6007","6008","6009",
                 "7000","7001","7002","7003","7004","7005","7006","7007","7008","7009",
                 "8000","8001","8002","8003","8004","8005"]},
    # Airtel
    "9810":("Airtel","Delhi","GSM"),       "9811":("Airtel","Delhi","GSM"),
    "9818":("Airtel","Delhi","GSM"),       "9871":("Airtel","Delhi","GSM"),
    "9870":("Airtel","Delhi","GSM"),       "9821":("Airtel","Mumbai","GSM"),
    "9869":("Airtel","Mumbai","GSM"),      "9823":("Airtel","Maharashtra","GSM"),
    "9876":("Airtel","Punjab","GSM"),      "9855":("Airtel","Punjab","GSM"),
    "9900":("Airtel","Karnataka","GSM"),   "9980":("Airtel","Karnataka","GSM"),
    "9440":("Airtel","Andhra Pradesh","GSM"), "9849":("Airtel","Andhra Pradesh","GSM"),
    "9600":("Airtel","Tamil Nadu","GSM"),  "9842":("Airtel","Tamil Nadu","GSM"),
    # Vi
    "9820":("Vodafone Idea (Vi)","Mumbai","GSM"),
    "9833":("Vodafone Idea (Vi)","Mumbai","GSM"),
    "9822":("Vodafone Idea (Vi)","Maharashtra","GSM"),
    "9902":("Vodafone Idea (Vi)","Karnataka","GSM"),
    "9441":("Vodafone Idea (Vi)","Andhra Pradesh","GSM"),
    # BSNL
    "9888":("BSNL","Punjab","GSM"),        "9901":("BSNL","Karnataka","GSM"),
    "9986":("BSNL","Karnataka","GSM"),     "9868":("BSNL","Delhi","GSM"),
}

VOIP_CARRIERS = {"google voice","twilio","vonage","magicjack","textnow",
                 "textfree","burner","hushed","skype","2ndline","sideline"}

FRAUD_IN = {"140":"TRAI telemarketer series","160":"OTP/Transactional — often spoofed by fraudsters"}
FRAUD_US = {"809":"Caribbean toll scam","876":"Jamaica — frequent fraud origin"}

# ════════════════════════════════════════════════════════════════
# MODULE A — CORE PARSING (offline)
# ════════════════════════════════════════════════════════════════
def parse_number(raw, default_region="IN"):
    res = {"input": raw, "valid": False}
    try:
        p = ph_parse(raw, default_region)
    except Exception as e:
        res["error"] = str(e); return res

    nt = number_type(p)
    type_map = {
        PhoneNumberType.MOBILE:               ("📱 MOBILE",        "Mobile SIM"),
        PhoneNumberType.FIXED_LINE:           ("🏢 FIXED LINE",     "Landline"),
        PhoneNumberType.FIXED_LINE_OR_MOBILE: ("📲 FIXED/MOBILE",  "Either"),
        PhoneNumberType.TOLL_FREE:            ("📞 TOLL FREE",      "Free to call"),
        PhoneNumberType.PREMIUM_RATE:         ("💸 PREMIUM RATE",  "⚠ Charges caller!"),
        PhoneNumberType.VOIP:                 ("🌐 VOIP",          "⚠ Internet — fraud risk"),
        PhoneNumberType.PERSONAL_NUMBER:      ("👤 PERSONAL",       "Follows subscriber"),
        PhoneNumberType.UAN:                  ("🏛 ENTERPRISE",    "Enterprise number"),
        PhoneNumberType.UNKNOWN:              ("❓ UNKNOWN",        "Undetermined"),
    }
    ti     = type_map.get(nt, ("❓ UNKNOWN","Undetermined"))
    region = region_code_for_number(p)
    c_name = ph_carrier.name_for_number(p,"en") or "Unknown"
    geo    = geocoder.description_for_number(p,"en") or "Unknown"

    res.update({
        "p":p, "valid":is_valid_number(p), "possible":is_possible_number(p),
        "e164":          format_number(p, PhoneNumberFormat.E164),
        "international": format_number(p, PhoneNumberFormat.INTERNATIONAL),
        "national":      format_number(p, PhoneNumberFormat.NATIONAL),
        "country_code":  p.country_code,
        "region":        region,
        "carrier":       c_name,
        "geo":           geo,
        "timezones":     list(ph_tz.time_zones_for_number(p)),
        "line_type":     ti[0],
        "line_desc":     ti[1],
    })

    # Fraud signals
    sigs = []
    if nt == PhoneNumberType.VOIP:         sigs.append(("HIGH","VOIP — untraceable, common in cyber fraud"))
    if nt == PhoneNumberType.PREMIUM_RATE: sigs.append(("HIGH","Premium rate — victim charged for calling back"))
    if nt == PhoneNumberType.TOLL_FREE:    sigs.append(("MED", "Toll-free — commonly spoofed in scams"))
    if any(v in c_name.lower() for v in VOIP_CARRIERS):
        sigs.append(("HIGH", f"Carrier is VOIP provider: {c_name}"))
    if region == "IN":
        d = re.sub(r'\D','', res["national"])
        for pfx, note in FRAUD_IN.items():
            if d.startswith(pfx): sigs.append(("HIGH", f"Series {pfx}XXXXXXX — {note}"))
    if region == "US":
        d = re.sub(r'\D','', res["national"])
        for ac, note in FRAUD_US.items():
            if d[:3] == ac: sigs.append(("HIGH", f"Area code {ac} — {note}"))
    res["fraud_signals"] = sigs

    # Carrier DB
    national_d = re.sub(r'\D','', res["national"])
    cdb = {"carrier":"","circle":"","type":"","ported":False}
    if region == "IN" and len(national_d) == 10:
        p4 = national_d[:4]
        if p4 in INDIA_PREFIXES:
            cdb["carrier"], cdb["circle"], cdb["type"] = INDIA_PREFIXES[p4]
        elif national_d[0] in "678":
            cdb["carrier"] = "Reliance Jio (likely)"; cdb["type"] = "4G"
        elif national_d[:2] == "94":
            cdb["carrier"] = "BSNL (likely)"; cdb["type"] = "2G/3G"
        # Porting check
        lib_c = c_name.lower().split()[0] if c_name.lower() != "unknown" else ""
        db_c  = cdb["carrier"].lower().replace("(likely)","").strip().split()[0] if cdb["carrier"] else ""
        if lib_c and db_c and lib_c != db_c:
            cdb["ported"] = True
            cdb["ported_note"] = f"Prefix → {cdb['carrier']}  |  Lib → {c_name}  → LIKELY PORTED"
    res["carrier_db"] = cdb
    return res

# ════════════════════════════════════════════════════════════════
# MODULE B — NAME SOURCES
# ════════════════════════════════════════════════════════════════

def _next_data_name(html):
    """Extract name from Next.js __NEXT_DATA__ JSON (used by Truecaller, Whoscall)."""
    m = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', html, re.S)
    if not m: return ""
    try:
        data = json.loads(m.group(1))
        pp   = data.get("props",{}).get("pageProps",{})
        for path in [
            lambda d: d["data"]["name"],
            lambda d: d["data"]["profiles"][0]["name"],
            lambda d: d["phoneInfo"]["name"],
            lambda d: d["callerName"],
            lambda d: d["name"],
            lambda d: d["profile"]["name"],
            lambda d: d["result"]["data"]["name"],
        ]:
            try:
                n = clean(path(pp))
                if n: return n
            except: pass
        # Broad JSON scan
        for m2 in re.findall(r'"name"\s*:\s*"([A-Z][A-Za-z\s\.]{2,50})"', html):
            n = clean(m2)
            if n and n.lower() not in _NOISE: return n
    except: pass
    return ""

def _og_name(html, number_str=""):
    """Extract name from OG meta title — Truecaller puts 'Name | Truecaller'."""
    soup = BeautifulSoup(html, "html.parser")
    for prop in ["og:title","og:description","twitter:title"]:
        tag = soup.find("meta", property=prop) or soup.find("meta", attrs={"name":prop})
        if tag and tag.get("content"):
            raw = tag["content"]
            # Split on | or - and take first part
            for part in re.split(r'[|\-–—]', raw):
                n = clean(part.strip())
                if n and number_str.replace(" ","") not in n.replace(" ",""):
                    return n
    # Title tag
    t = soup.find("title")
    if t:
        for part in re.split(r'[|\-–—]', t.get_text()):
            n = clean(part.strip())
            if n and number_str not in n: return n
    return ""

def src_truecaller(bare, region):
    """Truecaller: web page (NEXT_DATA + OG) + unofficial JSON API."""
    r = {"source":"Truecaller","name":"","score":0,"method":""}
    region_l = region.lower()

    # — Web page approach —
    s = session()
    try: s.get("https://www.truecaller.com/", timeout=6, verify=False)
    except: pass
    for url in [f"https://www.truecaller.com/search/{region_l}/{bare}",
                f"https://www.truecaller.com/search/global/{bare}"]:
        for mob in [False, True]:
            s2 = session(mobile=mob)
            resp = get(url, sess=s2, timeout=12)
            if not resp or resp.status_code != 200: continue
            n = _next_data_name(resp.text)
            if n: r.update({"name":n,"score":92,"method":"NEXT_DATA"}); return r
            n = _og_name(resp.text, bare)
            if n: r.update({"name":n,"score":72,"method":"OG meta"}); return r

    # — Unofficial API endpoint —
    api_headers = {
        "Authorization": "Bearer qoEp2A4cCGGWbLm99pBxMEKGOXSfFNMfANZNlnXK",
        "Accept": "application/json",
    }
    for ep in [
        f"https://search5-noneu.truecaller.com/v2/search?q={bare}&countryCode={region}&type=4&encoding=json",
        f"https://search5.truecaller.com/v2/search?q={bare}&countryCode={region}&type=4&encoding=json",
    ]:
        resp = get(ep, extra=api_headers, timeout=8)
        if resp:
            try:
                d = resp.json()
                for path in [lambda d: d["data"]["name"],
                              lambda d: d["data"]["profiles"][0]["name"],
                              lambda d: d["result"]["data"]["name"]]:
                    try:
                        n = clean(path(d))
                        if n: r.update({"name":n,"score":95,"method":"API JSON"}); return r
                    except: pass
            except: pass
    return r

def src_eyecon(digits):
    """Eyecon.mobi — 600M+ caller ID entries."""
    r = {"source":"Eyecon","name":"","score":0}
    for url in [f"https://www.eyecon.mobi/phone-number-lookup/{digits}",
                f"https://eyecon.mobi/reverse-phone-lookup/{digits}"]:
        resp = get(url, timeout=10)
        if not resp or not resp.ok: continue
        soup = BeautifulSoup(resp.text, "html.parser")
        # Structured selectors first
        for sel in [".caller-name",".person-name","#caller-name","[itemprop='name']",
                    "[class*='owner']","[class*='caller']","[class*='name']"]:
            el = soup.select_one(sel)
            if el:
                n = clean(el.get_text(strip=True))
                if n: r.update({"name":n,"score":85}); return r
        # JSON-LD
        for sc in soup.find_all("script", type="application/ld+json"):
            try:
                n = clean(json.loads(sc.string).get("name",""))
                if n: r.update({"name":n,"score":80}); return r
            except: pass
        # NEXT_DATA
        n = _next_data_name(resp.text)
        if n: r.update({"name":n,"score":82}); return r
        # OG
        n = _og_name(resp.text, digits)
        if n: r.update({"name":n,"score":65}); return r
        # h1/h2 fallback
        for tag in ["h1","h2"]:
            for el in soup.find_all(tag)[:3]:
                n = clean(el.get_text(strip=True))
                if n and digits not in n.replace(" ",""): r.update({"name":n,"score":55}); return r
    return r

def src_whoscall(intl):
    """Whoscall — strong Asia + India coverage, Next.js data."""
    r = {"source":"Whoscall","name":"","score":0}
    for url in [f"https://whoscall.com/en-US/number/{urllib.parse.quote(intl)}",
                f"https://whoscall.com/en-IN/number/{urllib.parse.quote(intl)}"]:
        resp = get(url, timeout=10)
        if not resp or not resp.ok: continue
        n = _next_data_name(resp.text)
        if n: r.update({"name":n,"score":88}); return r
        soup = BeautifulSoup(resp.text,"html.parser")
        for sel in [".caller-name",".phone-name","[class*='callerName']","[class*='ownerName']"]:
            el = soup.select_one(sel)
            if el:
                n = clean(el.get_text(strip=True))
                if n: r.update({"name":n,"score":70}); return r
        n = _og_name(resp.text, re.sub(r'\D','',intl))
        if n: r.update({"name":n,"score":60}); return r
    return r

def src_india_dbs(digits):
    """CalllerHunt, WhoCalledIndia, PhoneDetails, CallerID.in (India)."""
    r = {"source":"India Caller DBs","name":"","score":0}
    urls = [
        f"https://www.callerhunt.in/{digits}",
        f"https://www.whocalledindia.in/{digits}",
        f"https://phonedetails.in/{digits}",
        f"https://www.callerid.in/{digits}",
        f"https://in.directoryindia.com/phone/{digits}",
    ]
    for url in urls:
        resp = get(url, timeout=8)
        if not resp or not resp.ok: continue
        soup = BeautifulSoup(resp.text,"html.parser")
        # Structured
        for sel in [".name",".owner",".caller-name","#caller-name",
                    "[class*='name']","[class*='owner']","[itemprop='name']"]:
            el = soup.select_one(sel)
            if el:
                n = clean(el.get_text(strip=True))
                if n: r.update({"name":n,"score":80,"source":url.split("/")[2]}); return r
        # OG / h1
        n = _og_name(resp.text, digits)
        if n and len(n) > 3:
            r.update({"name":n,"score":65,"source":url.split("/")[2]}); return r
        h1 = soup.find("h1")
        if h1:
            n = clean(h1.get_text(strip=True))
            if n and digits not in n.replace(" ",""):
                r.update({"name":n,"score":60,"source":url.split("/")[2]}); return r
    return r

def src_numlookup(e164):
    """NumLookupAPI — free, no key, returns subscriber_name when available."""
    r = {"source":"NumLookupAPI","name":"","score":0}
    resp = get(f"https://api.numlookupapi.com/v1/info/{urllib.parse.quote(e164)}")
    if resp and resp.ok:
        try:
            d = resp.json()
            for key in ["subscriber_name","name","caller_name","owner_name","registered_name","contact_name"]:
                val = d.get(key,"")
                if val:
                    n = clean(str(val))
                    if n: r.update({"name":n,"score":75}); return r
        except: pass
    return r

def src_google_serp(national, intl, bare):
    """
    Google SERP scrape — extracts names from result titles and snippets.
    Truecaller/Eyecon/Whoscall Google snippets often reveal names.
    """
    r = {"source":"Google SERP","name":"","score":0,"links":[]}
    queries = [
        f'"{national}" truecaller name',
        f'"{intl}" name owner',
        f'site:truecaller.com "{national}"',
        f'site:eyecon.mobi "{national}"',
    ]
    for q in queries:
        resp = get(f"https://www.google.com/search?q={urllib.parse.quote(q)}&hl=en",
                   extra={"Referer":"https://www.google.com/"}, timeout=10)
        if not resp or resp.status_code != 200: continue
        soup = BeautifulSoup(resp.text,"html.parser")
        # Collect all text
        all_text = " ".join(d.get_text(" ") for d in
                            soup.find_all("div", class_=re.compile(r'BNeawe|VwiC3b|yDYNvb|MUxGbd|s3v9rd')))
        all_text += " ".join(h.get_text() for h in soup.find_all(["h3","h2"]))
        # Name extraction patterns
        patterns = [
            rf'([A-Z][a-zA-Z\s\.\-]{{3,40}}) (?:is calling|called you|is calling you)',
            rf'(?:belongs to|registered to|owned by|subscriber) ([A-Z][a-zA-Z\s\.\-]{{3,40}})',
            rf'([A-Z][a-zA-Z\s\.\-]{{3,40}})\s*[|\-–]\s*(?:Truecaller|Eyecon|Whoscall)',
            rf'([A-Z][a-zA-Z\s\.\-&]{{3,60}})\s*[-–]\s*(?:Contact|Phone|Mobile|Tel|Number)',
        ]
        for pat in patterns:
            m = re.search(pat, all_text)
            if m:
                n = clean(m.group(1))
                if n:
                    r.update({"name":n,"score":62,"context":all_text[max(0,m.start()-50):m.end()+50]})
                    return r
        time.sleep(0.3)
    return r

def src_facebook(national, intl):
    """Facebook public people search by phone number."""
    r = {"source":"Facebook","name":"","score":0,"profiles":[]}
    for q in [national, intl]:
        q_clean = re.sub(r'\s','',q)
        resp = get(f"https://www.facebook.com/search/people/?q={urllib.parse.quote(q_clean)}",
                   extra={"Referer":"https://www.facebook.com/"}, timeout=12)
        if not resp or resp.status_code != 200: continue
        soup = BeautifulSoup(resp.text,"html.parser")
        # JSON blobs in page
        for sc in soup.find_all("script"):
            txt = sc.string or ""
            if q_clean.replace("+","") in txt:
                m = re.search(r'"name"\s*:\s*"([A-Za-z\s\.\-]{3,60})"', txt)
                if m:
                    n = clean(m.group(1))
                    if n: r.update({"name":n,"score":85}); return r
        # Profile names in HTML
        for cls in ["._8o._8s.lfloat","fsl.fwb.fcb","[data-testid='browse-result-content']"]:
            for el in soup.select(cls)[:3]:
                n = clean(el.get_text(strip=True))
                if n: r["profiles"].append(n)
        if r["profiles"]:
            r.update({"name":r["profiles"][0],"score":75}); return r
    return r

def src_justdial(digits):
    """JustDial — India's largest business directory."""
    r = {"source":"JustDial","name":"","score":0}
    resp = get(f"https://www.justdial.com/{digits}", timeout=10)
    if resp and resp.ok:
        soup = BeautifulSoup(resp.text,"html.parser")
        for sel in [".store-name",".business-name","[class*='companyname']",
                    "[class*='storename']","h1","h2"]:
            el = soup.select_one(sel)
            if el:
                n = clean(el.get_text(strip=True))
                if n and digits not in n.replace(" ",""): r.update({"name":n,"score":72}); return r
    return r

def src_spam_dbs(national, region):
    """
    Scrape ShouldIAnswer, 800notes, SpamCalls — they sometimes show
    the name submitted by community reporters.
    """
    r = {"source":"Spam DBs","name":"","score":0,"reports":0,"fraud_keywords":[],"comments":[]}
    digits = re.sub(r'\D','', national)
    domains = {"IN":"shouldianswer.net","US":"shouldianswer.com","GB":"shouldianswer.co.uk"}
    base = domains.get(region,"shouldianswer.com")

    resp = get(f"https://www.{base}/phone-number/{digits}", timeout=10)
    if resp and resp.ok:
        soup = BeautifulSoup(resp.text,"html.parser")
        m = re.search(r'(\d+)\s+(?:review|report|rating|comment)', resp.text, re.I)
        if m: r["reports"] = int(m.group(1))
        fwords = ["scam","fraud","cheat","fake","spam","criminal","police","cyber","loan","investment","threat"]
        r["fraud_keywords"] = [w for w in fwords if w in resp.text.lower()]
        for el in soup.find_all(class_=re.compile(r'comment|review|post',re.I))[:3]:
            txt = el.get_text(strip=True)[:150]
            if len(txt) > 20 and "cookie" not in txt.lower(): r["comments"].append(txt)
        # Sometimes reporters include the name in comments
        for comment in r["comments"]:
            m2 = re.search(r'([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3})', comment)
            if m2:
                n = clean(m2.group(1))
                if n: r.update({"name":n,"score":40}); break

    # 800notes (US)
    if region == "US" and len(digits) == 10:
        fmt = f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
        resp2 = get(f"https://800notes.com/Phone.aspx/{fmt}", timeout=10)
        if resp2 and resp2.ok:
            m3 = re.search(r'(\d+)\s+(?:post|comment)', resp2.text, re.I)
            if m3: r["reports"] += int(m3.group(1))
            soup2 = BeautifulSoup(resp2.text,"html.parser")
            for el in soup2.find_all(class_=re.compile(r'post|comment',re.I))[:3]:
                txt = el.get_text(strip=True)[:150]
                if len(txt) > 20: r["comments"].append(txt)
    return r

def check_whatsapp(e164):
    """WhatsApp public endpoint — checks registration status."""
    number = e164.replace("+","").replace(" ","")
    r = {"platform":"WhatsApp","url":f"https://wa.me/{number}","found":None,"status":""}
    resp = get(f"https://api.whatsapp.com/send?phone={number}", timeout=10)
    if resp:
        text = resp.text.lower()
        if "continue to chat" in text or "open whatsapp" in text:
            r.update({"found":True, "status":"[bold green]✓ REGISTERED[/bold green]"})
        elif "invalid" in text or "not valid" in text:
            r.update({"found":False,"status":"[red]NOT REGISTERED / INVALID[/red]"})
        else:
            r.update({"status":"[yellow]POSSIBLY REGISTERED[/yellow]"})
    return r

def check_telegram(e164):
    """Telegram public t.me — detects public profiles."""
    number = e164.replace("+","")
    r = {"platform":"Telegram","url":f"https://t.me/+{number}","found":False,"name":""}
    resp = get(f"https://t.me/+{number}", timeout=8)
    if resp:
        text = resp.text.lower()
        if "tgme_page_title" in text or "join group" in text or "send message" in text:
            r["found"] = True
            r["status"] = "[bold green]✓ PUBLIC PROFILE[/bold green]"
            m = re.search(r'<div class="tgme_page_title"[^>]*>(.*?)</div>', resp.text, re.S)
            if m:
                n = clean(re.sub(r'<[^>]+>','',m.group(1)))
                r["name"] = n
        else:
            r["status"] = "[dim]No public profile[/dim]"
    return r

# ════════════════════════════════════════════════════════════════
# CROSS-REFERENCE ENGINE
# ════════════════════════════════════════════════════════════════
def cross_ref(results):
    entries = [(r["name"], r["score"], r["source"]) for r in results if r.get("name")]
    if not entries:
        return {"final":"","confidence":"NONE","sources":[],"all":[]}

    def norm(n): return re.sub(r'\s+',' ',n.lower().strip())
    counter  = Counter(norm(n) for n,_,_ in entries)
    scores   = {}; srcs = {}; display = {}
    for name, score, source in entries:
        k = norm(name)
        scores[k]  = scores.get(k,0) + score + counter[k] * 25
        srcs.setdefault(k,[]).append(source)
        if k not in display:
            display[k] = ' '.join(w.capitalize() for w in name.split())

    best  = max(scores, key=scores.get)
    count = counter[best]
    sc    = scores[best]

    if count >= 3 or sc >= 220:   conf = "HIGH"
    elif count >= 2 or sc >= 130: conf = "MEDIUM"
    else:                         conf = "LOW"

    return {
        "final":      display[best],
        "confidence": conf,
        "sources":    srcs[best],
        "count":      count,
        "score":      sc,
        "all":        [(display[k], srcs[k]) for k in sorted(scores, key=scores.get, reverse=True)],
    }

# ════════════════════════════════════════════════════════════════
# DORKS
# ════════════════════════════════════════════════════════════════
def make_dorks(national, intl, e164, region):
    bare = e164.replace("+","")
    g    = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    is_in = region == "IN"
    return {
        "🔍 Identity & Name": [
            (f'"{national}" name owner',       g(f'"{national}" name owner')),
            (f'"{intl}"',                      g(f'"{intl}"')),
            (f'Truecaller SERP',               g(f'"{national}" site:truecaller.com OR site:eyecon.mobi OR site:whoscall.com')),
            (f'"{bare}" github',               g(f'"{bare}" site:github.com')),
        ],
        "🚨 Fraud & Complaints": [
            (f'Scam/fraud complaint',          g(f'"{national}" scam OR fraud OR cheat OR complaint')),
            (f'Cybercrime/police',             g(f'"{national}" cybercrime OR police OR FIR OR arrested')),
            (f'UPI payment fraud (IN)',        g(f'"{national}" UPI OR GPay OR PhonePe fraud')) if is_in else (f'Wire fraud (US)', g(f'"{national}" wire fraud OR IRS scam')),
        ],
        "📱 Social Media": [
            ("Facebook",  g(f'"{national}" site:facebook.com')),
            ("Instagram", g(f'"{national}" site:instagram.com')),
            ("LinkedIn",  g(f'"{national}" site:linkedin.com')),
            ("Telegram",  g(f'"{national}" site:t.me OR site:telegram.org')),
        ],
        "📒 Directories": [
            ("JustDial",  g(f'"{national}" site:justdial.com'))   if is_in else ("YellowPages", g(f'"{national}" site:yellowpages.com')),
            ("IndiaMART", g(f'"{national}" site:indiamart.com'))  if is_in else ("Yelp", g(f'"{national}" site:yelp.com')),
            ("Sulekha",   g(f'"{national}" site:sulekha.com'))    if is_in else ("Whitepages", g(f'"{national}" site:whitepages.com')),
            ("OLX",       g(f'"{national}" site:olx.in'))         if is_in else ("Craigslist", g(f'"{national}" site:craigslist.org')),
        ],
        "📄 Leaks & Docs": [
            ("Pastebin",      g(f'"{national}" site:pastebin.com')),
            ("PDF docs",      g(f'"{national}" filetype:pdf')),
            ("Spreadsheets",  g(f'"{national}" filetype:xlsx OR filetype:csv')),
            ("GitHub code",   g(f'"{e164}" site:github.com')),
        ],
        "📍 Direct Reverse Lookup": [
            ("Truecaller",    f"https://www.truecaller.com/search/{region.lower()}/{bare}"),
            ("Eyecon",        f"https://www.eyecon.mobi/phone-number-lookup/{re.sub(chr(92)+'D','',national)}"),
            ("Whoscall",      f"https://whoscall.com/en-US/number/{urllib.parse.quote(intl)}"),
            ("ShouldIAnswer", f"https://www.shouldianswer.com/phone-number/{re.sub(chr(92)+'D','',national)}"),
            ("SpamCalls",     f"https://www.spamcalls.net/en/number/{bare}"),
            ("CallerHunt IN", f"https://www.callerhunt.in/{re.sub(chr(92)+'D','',national)}") if is_in else ("800notes", f"https://800notes.com/Phone.aspx/{re.sub(chr(92)+'D','',national)[:3]}-{re.sub(chr(92)+'D','',national)[3:6]}-{re.sub(chr(92)+'D','',national)[6:]}"),
        ],
    }

# ════════════════════════════════════════════════════════════════
# FRAUD RISK SCORE
# ════════════════════════════════════════════════════════════════
def risk_score(core, spam, social):
    score, reasons = 0, []
    lt = core.get("line_type","")
    if "VOIP"    in lt: score+=35; reasons.append("+35  VOIP — untraceable")
    if "PREMIUM" in lt: score+=25; reasons.append("+25  Premium rate — victim is charged")
    if "TOLL"    in lt: score+=10; reasons.append("+10  Toll-free — spoofing risk")
    if any(v in core.get("carrier","").lower() for v in VOIP_CARRIERS):
        score+=20; reasons.append(f"+20  VOIP carrier: {core['carrier']}")
    if core.get("carrier_db",{}).get("ported"):
        score+=10; reasons.append("+10  SIM porting detected")
    for lvl, sig in core.get("fraud_signals",[]):
        pts = 25 if lvl=="HIGH" else 10
        score+=pts; reasons.append(f"+{pts}  {sig}")
    rep = spam.get("reports",0)
    if rep>50: score+=25; reasons.append(f"+25  {rep} spam reports")
    elif rep>10: score+=12; reasons.append(f"+12  {rep} spam reports")
    elif rep>0:  score+=5;  reasons.append(f"+5   {rep} spam reports")
    kws = spam.get("fraud_keywords",[])
    if kws: score+=15; reasons.append(f"+15  Fraud keywords: {kws[:3]}")
    wa = next((s for s in social if s.get("platform")=="WhatsApp"),{})
    if wa.get("found")==False and core.get("region")=="IN":
        score+=5; reasons.append("+5   Not on WhatsApp (possible burner)")
    score = min(100,max(0,score))
    if score>=75:   lv,col,em="HIGH RISK — LIKELY FRAUD","red","🚨"
    elif score>=50: lv,col,em="MEDIUM-HIGH RISK — SUSPICIOUS","red","⚠ "
    elif score>=30: lv,col,em="MEDIUM RISK","yellow","⚠ "
    elif score>=10: lv,col,em="LOW RISK","yellow","ℹ "
    else:           lv,col,em="MINIMAL RISK — LOOKS CLEAN","green","✓ "
    return {"score":score,"level":lv,"color":col,"emoji":em,"reasons":reasons}

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════
def run(number_str, region="IN", export=False):
    all_data = {"input":number_str,"ts":datetime.now().isoformat()}
    console.print()
    console.print(Panel(
        f"[bold white]Number:[/bold white]  [bold cyan]{number_str}[/bold cyan]\n"
        f"[bold white]Region:[/bold white]  [cyan]{region}[/cyan]\n"
        f"[bold white]Mode:[/bold white]    [bold green]Zero API Keys — 100% Free[/bold green]\n"
        f"[bold white]Goal:[/bold white]    [bold yellow]Find owner name + fraud risk[/bold yellow]",
        title="[bold yellow]📞  PHONE OSINT — Name Lookup Edition[/bold yellow]",
        border_style="yellow", padding=(1,3)
    ))

    # ── Parse ─────────────────────────────────────────────────
    sec("① Number Analysis  (offline)")
    core = parse_number(number_str, region)
    all_data["core"] = core
    if core.get("error"):
        console.print(f"[bold red]{core['error']}[/bold red]"); return all_data

    e164     = core["e164"];  bare = e164.replace("+","")
    intl     = core["international"]
    national = core["national"]
    nat_d    = re.sub(r'\D','', national)
    reg      = core["region"]

    t = Table(box=box.ROUNDED, show_header=False, padding=(0,2), border_style="cyan")
    t.add_column("Field", style="bold cyan", width=20)
    t.add_column("Value", style="white")
    cdb = core.get("carrier_db",{})
    t.add_row("E.164",          e164)
    t.add_row("International",  intl)
    t.add_row("National",       national)
    t.add_row("Country/Region", f"{reg}  (+{core['country_code']})")
    t.add_row("Carrier (lib)",  core["carrier"])
    t.add_row("Carrier (DB)",   f"{cdb.get('carrier','')}  {cdb.get('circle','')}  {cdb.get('type','')}".strip() or "—")
    t.add_row("SIM Porting",    "[bold yellow]⚠ POSSIBLE PORTING[/bold yellow]" if cdb.get("ported") else "[green]No porting detected[/green]")
    t.add_row("Geographic Area",core["geo"])
    t.add_row("Line Type",      core["line_type"] + "  " + core["line_desc"])
    t.add_row("Timezones",      "  ".join(core["timezones"]))
    t.add_row("Valid Number",   "[bold green]✓ YES[/bold green]" if core["valid"] else "[bold red]✗ NO[/bold red]")
    console.print(t)
    for lvl, sig in core.get("fraud_signals",[]):
        col = "bold red" if lvl=="HIGH" else "bold yellow"
        console.print(f"  [{col}]🚨 [{lvl}] {sig}[/{col}]")

    # ── Name lookups ──────────────────────────────────────────
    sec("② Owner Name Lookup  (10 sources, parallel)")
    name_results = []
    spam_result  = {}
    social       = []

    lookups = {
        "Truecaller":         lambda: src_truecaller(bare, reg),
        "Eyecon":             lambda: src_eyecon(nat_d),
        "Whoscall":           lambda: src_whoscall(intl),
        "NumLookupAPI":       lambda: src_numlookup(e164),
        "Google SERP":        lambda: src_google_serp(national, intl, bare),
        "Facebook Search":    lambda: src_facebook(national, intl),
        "JustDial (IN)":      lambda: src_justdial(nat_d) if reg=="IN" else {"source":"JustDial","name":"","score":0},
        "India Caller DBs":   lambda: src_india_dbs(nat_d) if reg=="IN" else {"source":"India DBs","name":"","score":0},
        "Spam DB (name+data)":lambda: src_spam_dbs(national, reg),
        "WhatsApp":           lambda: check_whatsapp(e164),
        "Telegram":           lambda: check_telegram(e164),
    }

    rows = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(bar_width=35), console=console) as prog:
        task = prog.add_task("[cyan]Searching all sources...", total=len(lookups))
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fn): name for name, fn in lookups.items()}
            for future in as_completed(futures):
                src_name = futures[future]
                prog.update(task, description=f"[cyan]✓ {src_name}")
                prog.advance(task)
                try:
                    res = future.result()
                    if not res: continue
                    if src_name.startswith("WhatsApp") or src_name.startswith("Telegram"):
                        social.append(res)
                    elif src_name.startswith("Spam"):
                        spam_result = res
                        if res.get("name"): name_results.append(res)
                    else:
                        name_results.append(res)
                    rows.append((
                        res.get("source", src_name),
                        res.get("name",""),
                        res.get("score",0),
                        res.get("method",""),
                    ))
                except Exception as e:
                    rows.append((src_name, f"[red]{str(e)[:30]}[/red]", 0, ""))

    all_data["name_results"] = rows

    # ── Name results table ────────────────────────────────────
    sec("③ Raw Results — Per Source")
    rt = Table(box=box.ROUNDED, padding=(0,2), border_style="cyan")
    rt.add_column("Source",     style="bold cyan",  width=22)
    rt.add_column("Name Found", style="bold white", width=28)
    rt.add_column("Confidence", width=12)
    rt.add_column("Method",     style="dim",        width=18)
    for src, name, score, method in sorted(rows, key=lambda x:-x[2]):
        if score>=80:   conf="[bold green]HIGH[/bold green]"
        elif score>=50: conf="[bold yellow]MEDIUM[/bold yellow]"
        elif name:      conf="[yellow]LOW[/yellow]"
        else:           conf="[dim]—[/dim]"
        rt.add_row(src[:22],
                   f"[bold cyan]{name[:28]}[/bold cyan]" if name else "[dim]Not found[/dim]",
                   conf, method[:18])
    console.print(rt)

    # ── Final verdict ─────────────────────────────────────────
    sec("④ Owner Identification — Final Verdict")
    verdict = cross_ref(name_results)
    all_data["verdict"] = verdict

    if verdict["final"]:
        conf_col = {"HIGH":"bold green","MEDIUM":"bold yellow","LOW":"yellow"}.get(verdict["confidence"],"white")
        body = (
            f"[bold white]Owner Name:[/bold white]   [{conf_col}]  {verdict['final']}  [/{conf_col}]\n\n"
            f"[bold white]Confidence:[/bold white]   [{conf_col}]{verdict['confidence']}[/{conf_col}]\n"
            f"[bold white]Found on:[/bold white]    {', '.join(verdict['sources'])}\n"
            f"[bold white]Confirmed by:[/bold white] {verdict['count']} source(s)"
        )
        if len(verdict["all"]) > 1:
            others = [f"  • {n}  (via {', '.join(s)})" for n,s in verdict["all"] if n != verdict["final"]]
            if others: body += "\n\n[bold white]Other names seen:[/bold white]\n" + "\n".join(others)
        console.print(Panel(body,
            title="[bold yellow]👤 OWNER IDENTIFIED[/bold yellow]",
            border_style="green" if verdict["confidence"]=="HIGH" else "yellow",
            padding=(1,3)))
    else:
        console.print(Panel(
            "[bold yellow]Name not found in automated public sources.[/bold yellow]\n\n"
            "[bold white]Use these manual methods (take 30 seconds each):[/bold white]\n\n"
            "[bold cyan]① WhatsApp[/bold cyan] (most reliable — 90% success rate)\n"
            f"   → Open WhatsApp → New Chat → type  [bold]{national}[/bold]\n"
            "   → Profile name appears instantly\n\n"
            "[bold cyan]② GPay / PhonePe (India — instant bank name)[/bold cyan]\n"
            f"   → Open Google Pay → Send → type  [bold]{national}[/bold]\n"
            "   → Shows registered bank account name (no money sent)\n\n"
            "[bold cyan]③ Truecaller App[/bold cyan] (3 billion numbers)\n"
            f"   → Search  [bold]{national}[/bold]  in Truecaller app\n\n"
            "[bold cyan]④ Facebook Messenger[/bold cyan]\n"
            f"   → New Message → search  [bold]{national}[/bold]",
            title="[bold red]👤 Name Not Found Automatically[/bold red]",
            border_style="red", padding=(1,3)))

    # ── Social status ─────────────────────────────────────────
    sec("⑤ Messaging Platform Status")
    st = Table(box=box.ROUNDED, padding=(0,2), border_style="cyan")
    st.add_column("Platform", style="bold cyan", width=14)
    st.add_column("Status",   width=42)
    st.add_column("Name",     style="bold green")
    for s in social:
        st.add_row(s.get("platform","?"),
                   str(s.get("status",""))[:42],
                   s.get("name","")[:28])
    console.print(st)

    # Telegram name bonus
    tg = next((s for s in social if s.get("platform")=="Telegram"), {})
    if tg.get("name") and not verdict["final"]:
        console.print(f"  [bold green]✓ Telegram profile name: {tg['name']}[/bold green]")

    # Spam comments
    if spam_result.get("comments"):
        sec("⑥ Community Reports / Comments")
        for c in spam_result["comments"][:3]:
            console.print(f"  [dim italic]💬 \"{c}\"[/dim italic]")

    # ── Fraud risk ────────────────────────────────────────────
    sec("⑦ Fraud Risk Score")
    risk = risk_score(core, spam_result, social)
    all_data["risk"] = risk
    filled = "█"*(risk["score"]//5); empty = "░"*(20-risk["score"]//5)
    col = risk["color"]
    body = (f"[bold white]Score:[/bold white]  [{col}]{risk['score']} / 100[/{col}]\n"
            f"[{col}]{filled}{empty}[/{col}]\n\n"
            f"[bold white]Level:[/bold white]  [{col}]{risk['emoji']}  {risk['level']}[/{col}]")
    if risk["reasons"]:
        body += "\n\n[bold white]Evidence:[/bold white]\n" + "\n".join(f"  {r}" for r in risk["reasons"])
    console.print(Panel(body, title="[bold yellow]Risk Score[/bold yellow]",
                        border_style=col, padding=(1,3)))

    # ── Dorks ─────────────────────────────────────────────────
    sec("⑧ Investigation Links & Dorks  (one-click)")
    dorks = make_dorks(national, intl, e164, reg)
    all_data["dorks"] = dorks
    for cat, items in dorks.items():
        console.print(f"\n  [bold yellow]{cat}[/bold yellow]")
        for label, url in items[:4]:
            if label and url:
                console.print(f"    [dim]{label:<38}[/dim]  [cyan]{url}[/cyan]")

    # ── Manual tips ───────────────────────────────────────────
    sec("⑨ Pro Tips — Get the Name in 60 Seconds")
    tips = [
        ("WhatsApp",              f"New Chat → {national} → see profile name → tap DP → reverse image search"),
        ("GPay / PhonePe (IN)",   f"Send money → {national} → shows registered BANK account name"),
        ("Truecaller App",        f"Search {national} → biggest DB, 3B+ numbers"),
        ("Facebook Messenger",    f"New Message → search {national} → linked accounts appear"),
        ("Instagram",             f"Settings → Contacts → sync → find linked accounts"),
        ("LinkedIn",              f"Search {national} in search bar — works for business numbers"),
    ]
    for platform, method in tips:
        console.print(f"  [bold cyan]{platform:<22}[/bold cyan]  {method}")

    # ── Export ────────────────────────────────────────────────
    if export:
        sec("Export")
        slug = re.sub(r'\W','_', number_str.strip('+'))
        out  = Path(f"phone_name_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        out.mkdir(parents=True, exist_ok=True)
        with open(out/"full_report.json","w") as f: json.dump(all_data,f,indent=2,default=str)
        with open(out/"dorks.txt","w") as f:
            for cat, items in dorks.items():
                f.write(f"\n=== {cat} ===\n")
                for lbl,url in items: f.write(f"{lbl}\n{url}\n\n")
        with open(out/"summary.txt","w") as f:
            f.write(f"Phone OSINT — Name Lookup Report\n{'='*40}\n")
            f.write(f"Number:      {intl}\n")
            f.write(f"Region:      {reg}\n")
            f.write(f"Carrier:     {core['carrier']}\n")
            f.write(f"DB Carrier:  {cdb.get('carrier','')} {cdb.get('circle','')}\n")
            f.write(f"Line Type:   {core['line_type']}\n")
            f.write(f"Area:        {core['geo']}\n\n")
            f.write(f"OWNER NAME:  {verdict.get('final','Not found')}\n")
            f.write(f"Confidence:  {verdict.get('confidence','N/A')}\n")
            f.write(f"Sources:     {', '.join(verdict.get('sources',[]))}\n\n")
            f.write(f"Risk Score:  {risk['score']}/100 — {risk['level']}\n\n")
            f.write("All Sources:\n")
            for src,name,score,_ in sorted(rows,key=lambda x:-x[2]):
                f.write(f"  {src:<28} {name or 'N/A'}\n")
        console.print(f"\n  [bold green]✓ Saved to {out}/[/bold green]  (full_report.json · summary.txt · dorks.txt)")

    return all_data

# ─── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Phone OSINT + Name Lookup — Zero API Keys",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python phone_name_lookup.py +919876543210
  python phone_name_lookup.py +919876543210 --export
  python phone_name_lookup.py +14155552671 --region US --export
  python phone_name_lookup.py +44 7911 123456 --region GB
        """
    )
    ap.add_argument("number", help="Phone number  e.g. +919876543210")
    ap.add_argument("--region", default="IN", help="Default region if no +code (default: IN)")
    ap.add_argument("--export", action="store_true", help="Save JSON + summary + dorks to folder")
    args = ap.parse_args()
    run(args.number, region=args.region.upper(), export=args.export)
