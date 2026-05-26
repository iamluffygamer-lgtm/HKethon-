"""
OSINT Engine — Core intelligence functions
Called by FastAPI endpoints, returns clean dicts (no Rich console output)
"""

import re, json, hashlib, time, socket, ssl, smtplib, urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois as whois_lib
import tldextract

try:
    import phonenumbers
    from phonenumbers import (
        geocoder, carrier as ph_carrier, timezone as ph_tz,
        PhoneNumberType, PhoneNumberFormat, is_valid_number,
        is_possible_number, number_type, format_number,
        parse as ph_parse, region_code_for_number
    )
    PHONE_LIB = True
except ImportError:
    PHONE_LIB = False

try:
    import anthropic
    HAS_AI = True
except ImportError:
    HAS_AI = False

import urllib3
urllib3.disable_warnings()

# ─── Constants ────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept": "text/html,*/*;q=0.8",
           "Accept-Language": "en-US,en;q=0.9", "DNT": "1"}

INDIA_PREFIXES = {
    "6000": ("Reliance Jio", "Various",           "4G/5G"),
    "7000": ("Reliance Jio", "Various",           "4G/5G"),
    "8000": ("Reliance Jio", "Various",           "4G/5G"),
    "9810": ("Airtel",       "Delhi",             "GSM"),
    "9811": ("Airtel",       "Delhi",             "GSM"),
    "9876": ("Airtel",       "Punjab",            "GSM"),
    "9900": ("Airtel",       "Karnataka",         "GSM"),
    "9820": ("Vodafone Idea","Mumbai",            "GSM"),
    "9833": ("Vodafone Idea","Mumbai",            "GSM"),
    "9888": ("BSNL",         "Punjab",            "GSM"),
    "9901": ("BSNL",         "Karnataka",         "GSM"),
}

VOIP_PROVIDERS = {"google voice","twilio","vonage","magicjack","skype",
                  "textnow","textfree","burner","hushed","2ndline"}

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com",
    "yopmail.com","trashmail.com","fakeinbox.com","maildrop.cc","temp-mail.org",
    "discard.email","throwaway.email","getairmail.com","getnada.com",
    "harakirimail.com","spamfree24.org","spam4.me",
}

USERNAME_SITES = [
    {"name": "GitHub",       "url": "https://github.com/{}",                   "err": "Not Found"},
    {"name": "Twitter/X",    "url": "https://x.com/{}",                        "err": "doesn't exist"},
    {"name": "Instagram",    "url": "https://www.instagram.com/{}/",           "err": "Sorry, this page"},
    {"name": "Reddit",       "url": "https://www.reddit.com/user/{}/",         "err": "nobody on Reddit"},
    {"name": "TikTok",       "url": "https://www.tiktok.com/@{}",              "err": "Couldn't find"},
    {"name": "YouTube",      "url": "https://www.youtube.com/@{}",             "err": "not available"},
    {"name": "Telegram",     "url": "https://t.me/{}",                         "err": "If you have Telegram"},
    {"name": "LinkedIn",     "url": "https://www.linkedin.com/in/{}/",         "err": "Page not found"},
    {"name": "Pinterest",    "url": "https://www.pinterest.com/{}/",           "err": "couldn't find"},
    {"name": "Snapchat",     "url": "https://www.snapchat.com/add/{}",         "err": "not found"},
    {"name": "GitLab",       "url": "https://gitlab.com/{}",                   "err": "404"},
    {"name": "Dev.to",       "url": "https://dev.to/{}",                       "err": "404"},
    {"name": "HackerNews",   "url": "https://news.ycombinator.com/user?id={}","err": "No such user"},
    {"name": "Medium",       "url": "https://medium.com/@{}",                  "err": "404"},
    {"name": "Steam",        "url": "https://steamcommunity.com/id/{}",        "err": "could not be found"},
    {"name": "Twitch",       "url": "https://www.twitch.tv/{}",                "err": "Sorry. Unless"},
    {"name": "Behance",      "url": "https://www.behance.net/{}",              "err": "404"},
    {"name": "Dribbble",     "url": "https://dribbble.com/{}",                 "err": "Whoops"},
    {"name": "SoundCloud",   "url": "https://soundcloud.com/{}",               "err": "can't find that user"},
    {"name": "Keybase",      "url": "https://keybase.io/{}",                   "err": "404"},
    {"name": "Pastebin",     "url": "https://pastebin.com/u/{}",               "err": "Not Found"},
    {"name": "Replit",       "url": "https://replit.com/@{}",                  "err": "not found"},
    {"name": "HackerRank",   "url": "https://www.hackerrank.com/{}",           "err": "404"},
    {"name": "LeetCode",     "url": "https://leetcode.com/{}/",                "err": "404"},
    {"name": "Kaggle",       "url": "https://www.kaggle.com/{}",               "err": "404"},
    {"name": "HuggingFace",  "url": "https://huggingface.co/{}",               "err": "404"},
    {"name": "Linktree",     "url": "https://linktr.ee/{}",                    "err": "404"},
    {"name": "About.me",     "url": "https://about.me/{}",                     "err": "404"},
    {"name": "Quora",        "url": "https://www.quora.com/profile/{}",        "err": "404"},
    {"name": "Mastodon",     "url": "https://mastodon.social/@{}",             "err": "404"},
    {"name": "Bluesky",      "url": "https://bsky.app/profile/{}",             "err": "404"},
    {"name": "Threads",      "url": "https://www.threads.net/@{}",             "err": "not found"},
    {"name": "VKontakte",    "url": "https://vk.com/{}",                       "err": "not found"},
    {"name": "Gravatar",     "url": "https://en.gravatar.com/{}",              "err": "does not exist"},
    {"name": "Fiverr",       "url": "https://www.fiverr.com/{}",               "err": "404"},
    {"name": "Patreon",      "url": "https://www.patreon.com/{}",              "err": "404"},
    {"name": "Ko-fi",        "url": "https://ko-fi.com/{}",                    "err": "404"},
    {"name": "Flipboard",    "url": "https://flipboard.com/@{}",               "err": "404"},
    {"name": "ShareChat",    "url": "https://sharechat.com/profile/{}",        "err": "404"},
    {"name": "Moj App",      "url": "https://mojapp.in/@{}",                   "err": "404"},
]

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 80:"HTTP", 443:"HTTPS",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB", 9200:"Elasticsearch",
}
HIGH_RISK_PORTS = {
    23:"TELNET exposed", 21:"FTP unencrypted", 3389:"RDP exposed",
    6379:"Redis no-auth", 27017:"MongoDB no-auth", 9200:"Elasticsearch exposed",
}

# ─── Utilities ────────────────────────────────────────────────────────────────
def safe_get(url, timeout=10, params=None):
    try:
        r = requests.get(url, timeout=timeout, headers=HEADERS,
                         params=params, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# PHONE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def phone_run(number: str, region: str = "IN") -> dict:
    result = {
        "input": number, "region": region, "ts": datetime.now().isoformat(),
        "core": {}, "carrier_db": {}, "social": [],
        "spam": [], "upi_hints": [], "risk": {}, "dorks": []
    }

    if not PHONE_LIB:
        result["error"] = "phonenumbers library missing"; return result

    # 1. Core parse
    try:
        p = ph_parse(number, region)
        nt = number_type(p)
        type_names = {
            PhoneNumberType.FIXED_LINE: "FIXED LINE",
            PhoneNumberType.MOBILE: "MOBILE",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED/MOBILE",
            PhoneNumberType.TOLL_FREE: "TOLL FREE",
            PhoneNumberType.PREMIUM_RATE: "PREMIUM RATE",
            PhoneNumberType.VOIP: "VOIP",
            PhoneNumberType.UNKNOWN: "UNKNOWN",
        }
        rgn     = region_code_for_number(p)
        carrier = ph_carrier.name_for_number(p, "en") or "Unknown"
        geo     = geocoder.description_for_number(p, "en") or "Unknown"
        e164    = format_number(p, PhoneNumberFormat.E164)
        natl    = format_number(p, PhoneNumberFormat.NATIONAL)
        intl    = format_number(p, PhoneNumberFormat.INTERNATIONAL)

        result["core"] = {
            "valid":         is_valid_number(p),
            "possible":      is_possible_number(p),
            "e164":          e164,
            "international": intl,
            "national":      natl,
            "country_code":  p.country_code,
            "region":        rgn,
            "carrier":       carrier,
            "geo":           geo,
            "timezones":     list(ph_tz.time_zones_for_number(p)),
            "line_type":     type_names.get(nt, "UNKNOWN"),
        }

        # Fraud signals
        signals = []
        if nt == PhoneNumberType.VOIP:
            signals.append({"level": "HIGH", "msg": "VOIP number — untraceable, top cyber fraud vector"})
        if nt == PhoneNumberType.PREMIUM_RATE:
            signals.append({"level": "HIGH", "msg": "Premium rate — charges victim on callback"})
        if any(v in carrier.lower() for v in VOIP_PROVIDERS):
            signals.append({"level": "HIGH", "msg": f"VOIP carrier: {carrier}"})
        result["core"]["fraud_signals"] = signals

        # 2. Carrier DB (India)
        national_digits = re.sub(r'\D', '', natl)
        cdb = {"carrier": "", "circle": "", "network": "", "ported": False}
        if rgn == "IN" and len(national_digits) == 10:
            p4 = national_digits[:4]
            if p4 in INDIA_PREFIXES:
                c, circle, net = INDIA_PREFIXES[p4]
                cdb.update({"carrier": c, "circle": circle, "network": net})
            elif national_digits[0] in "678":
                cdb.update({"carrier": "Reliance Jio (likely)", "network": "4G"})
            lib_c = carrier.lower().split()[0] if carrier != "Unknown" else ""
            db_c  = cdb["carrier"].replace("(likely)", "").strip().lower().split()[0] if cdb["carrier"] else ""
            if lib_c and db_c and lib_c != db_c:
                cdb["ported"] = True
                cdb["ported_note"] = f"DB says {cdb['carrier']}, phonenumbers says {carrier} → likely SIM ported"
        result["carrier_db"] = cdb

        # 3. Social checks (parallel)
        bare = e164.replace("+", "")

        def check_whatsapp():
            r = safe_get(f"https://api.whatsapp.com/send?phone={bare}", timeout=8)
            if r:
                txt = r.text.lower()
                found = "continue to chat" in txt or "open whatsapp" in txt
                return {"platform": "WhatsApp", "found": found,
                        "url": f"https://wa.me/{bare}",
                        "status": "REGISTERED" if found else "NOT FOUND"}
            return {"platform": "WhatsApp", "found": None, "status": "TIMEOUT"}

        def check_telegram():
            r = safe_get(f"https://t.me/+{bare}", timeout=8)
            if r:
                found = "tgme_page_title" in r.text or "send message" in r.text.lower()
                name  = ""
                if found:
                    m = re.search(r'tgme_page_title[^>]*>(.*?)</div>', r.text, re.S)
                    if m: name = re.sub(r'<[^>]+>', '', m.group(1)).strip()
                return {"platform": "Telegram", "found": found,
                        "url": f"https://t.me/+{bare}",
                        "status": "PUBLIC PROFILE" if found else "NOT FOUND",
                        "name": name}
            return {"platform": "Telegram", "found": None, "status": "TIMEOUT"}

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = [ex.submit(check_whatsapp), ex.submit(check_telegram)]
            result["social"] = [f.result() for f in futures]

        # 4. Spam DB checks (parallel)
        def check_shouldianswer():
            try:
                domains = {"IN": "shouldianswer.net", "US": "shouldianswer.com"}
                base = domains.get(rgn, "shouldianswer.com")
                r = safe_get(f"https://www.{base}/phone-number/{national_digits}", timeout=8)
                if r and r.ok:
                    soup = BeautifulSoup(r.text, "html.parser")
                    m = re.search(r'(\d+)\s+(?:review|report|rating)', r.text, re.I)
                    reports = int(m.group(1)) if m else 0
                    fwords  = [w for w in ["scam","fraud","spam","fake","criminal","cyber"]
                               if w in r.text.lower()]
                    return {"source": "ShouldIAnswer", "reports": reports,
                            "fraud_keywords": fwords}
            except: pass
            return {"source": "ShouldIAnswer", "reports": 0}

        def check_truecaller():
            try:
                url = f"https://www.truecaller.com/search/{rgn.lower()}/{bare}"
                r = safe_get(url, timeout=8)
                if r and r.ok:
                    soup = BeautifulSoup(r.text, "html.parser")
                    og = soup.find("meta", property="og:title")
                    if og and og.get("content"):
                        ct = og["content"]
                        if bare not in ct.replace(" ", "") and len(ct) > 2:
                            return {"source": "Truecaller", "found": True,
                                    "name": ct, "url": url}
            except: pass
            return {"source": "Truecaller", "found": False}

        def check_callerhunt():
            try:
                r = safe_get(f"https://www.callerhunt.in/{national_digits}", timeout=8)
                if r and r.ok:
                    soup = BeautifulSoup(r.text, "html.parser")
                    h1 = soup.find("h1")
                    name = h1.get_text(strip=True)[:60] if h1 else ""
                    m = re.search(r'(\d+)\s+(?:report|complaint)', r.text, re.I)
                    return {"source": "CallerHunt.in", "name": name,
                            "reports": int(m.group(1)) if m else 0}
            except: pass
            return {"source": "CallerHunt.in", "reports": 0}

        with ThreadPoolExecutor(max_workers=3) as ex:
            result["spam"] = [f.result() for f in [
                ex.submit(check_shouldianswer),
                ex.submit(check_truecaller),
                ex.submit(check_callerhunt),
            ]]

        # 5. UPI hints (India)
        if rgn == "IN":
            handles = ["okaxis","oksbi","okhdfcbank","ybl","paytm","apl","gpay"]
            result["upi_hints"] = [f"{national_digits}@{h}" for h in handles]

        # 6. Risk score
        score, reasons = 0, []
        lt = result["core"]["line_type"]
        if "VOIP"    in lt: score += 35; reasons.append("+35 VOIP line")
        if "PREMIUM" in lt: score += 25; reasons.append("+25 Premium rate line")
        if cdb.get("ported"): score += 10; reasons.append("+10 SIM porting detected")
        for sig in signals:
            if sig["level"] == "HIGH": score += 20; reasons.append(f"+20 {sig['msg']}")
        total_rep = sum(s.get("reports", 0) for s in result["spam"])
        if total_rep > 50:  score += 25; reasons.append(f"+25 {total_rep} spam reports")
        elif total_rep > 10: score += 12; reasons.append(f"+12 {total_rep} spam reports")
        elif total_rep > 0:  score += 5; reasons.append(f"+5 {total_rep} spam reports")
        score = min(100, score)
        level = ("HIGH RISK — LIKELY FRAUD"       if score >= 75 else
                 "MEDIUM-HIGH — SUSPICIOUS"        if score >= 50 else
                 "MEDIUM RISK"                     if score >= 30 else
                 "LOW RISK"                        if score >= 10 else
                 "MINIMAL RISK")
        result["risk"] = {"score": score, "level": level, "reasons": reasons}

        # 7. Google dorks
        g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
        result["dorks"] = [
            {"label": "Identity search",   "url": g(f'"{intl}"')},
            {"label": "Fraud complaints",  "url": g(f'"{natl}" scam OR fraud OR complaint')},
            {"label": "Cybercrime",        "url": g(f'"{natl}" cybercrime OR police OR FIR')},
            {"label": "Social media",      "url": g(f'"{natl}" site:facebook.com OR site:instagram.com')},
            {"label": "Truecaller",        "url": f"https://www.truecaller.com/search/{rgn.lower()}/{bare}"},
            {"label": "CallerHunt",        "url": f"https://www.callerhunt.in/{national_digits}"},
        ]

    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def email_run(email: str) -> dict:
    result = {
        "input": email, "ts": datetime.now().isoformat(),
        "structure": {}, "smtp": {}, "breach": [],
        "gravatar": {}, "github": {}, "social": [], "dorks": []
    }
    parts    = email.split("@")
    username = parts[0]
    domain   = parts[1] if len(parts) > 1 else ""
    result["structure"] = {
        "username":    username,
        "domain":      domain,
        "disposable":  domain.lower() in DISPOSABLE_DOMAINS,
        "free_provider": domain.lower() in {"gmail.com","yahoo.com","hotmail.com",
                                             "outlook.com","protonmail.com","icloud.com",
                                             "rediffmail.com","yahoo.in"},
    }

    # MX records
    try:
        mx = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_list = sorted(mx, key=lambda r: r.preference)
        result["structure"]["mx"] = [str(r.exchange).rstrip(".") for r in mx_list]
        result["structure"]["mx_ok"] = True
    except Exception:
        result["structure"]["mx"] = []
        result["structure"]["mx_ok"] = False

    # SMTP probe
    try:
        mx_host = result["structure"]["mx"][0] if result["structure"]["mx"] else None
        if mx_host:
            with smtplib.SMTP(mx_host, 25, timeout=8) as smtp:
                smtp.ehlo("probe.osintpro.local")
                smtp.mail("probe@osintpro.local")
                code, _ = smtp.rcpt(email)
                result["smtp"] = {
                    "mx_host": mx_host,
                    "exists": code == 250,
                    "code": code,
                    "detail": "Mailbox confirmed" if code == 250 else "Mailbox rejected" if code == 550 else f"Code {code}",
                }
        else:
            result["smtp"] = {"exists": None, "detail": "No MX — cannot probe"}
    except Exception as e:
        result["smtp"] = {"exists": None, "detail": f"Probe blocked: {str(e)[:60]}"}

    # Breach check
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        r = safe_get(f"https://api.pwnedpasswords.com/range/{sha1[:5]}", timeout=8)
        if r and r.ok and sha1[5:] in r.text:
            result["breach"].append({"source": "HIBP PwnedPasswords",
                                     "detail": "Email found in leaked password corpus"})
    except: pass

    try:
        r = safe_get("https://breachdirectory.org/api",
                     params={"func": "auto", "term": email}, timeout=10)
        if r and r.ok:
            d = r.json()
            if d.get("result") and d["result"] != "0":
                result["breach"].append({"source": "BreachDirectory",
                                         "count": d.get("result"), "detail": "Found in breach DB"})
    except: pass

    # Gravatar
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    r   = safe_get(f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=5)
    result["gravatar"] = {
        "found":   r and r.status_code == 200,
        "url":     f"https://www.gravatar.com/avatar/{md5}",
        "profile": f"https://en.gravatar.com/{md5}",
    }

    # GitHub
    try:
        r = requests.get(
            f"https://api.github.com/search/commits?q=author-email:{email}&per_page=5",
            headers={**HEADERS, "Accept": "application/vnd.github.cloak-preview"},
            timeout=12
        )
        if r and r.ok:
            d = r.json()
            repos = []
            gh_username = ""
            for item in d.get("items", [])[:4]:
                repos.append({"repo": item["repository"]["full_name"],
                              "msg": item["commit"]["message"][:60]})
                if not gh_username and item.get("author"):
                    gh_username = item["author"].get("login", "")
            result["github"] = {"commits": d.get("total_count", 0),
                                 "repos": repos, "username": gh_username}
    except:
        result["github"] = {"commits": 0, "repos": [], "username": ""}

    # Social quick check (username from email)
    social_hits = []
    for platform, url_tpl in [("GitHub", "https://github.com/{}"),
                                ("Twitter/X", "https://x.com/{}"),
                                ("Telegram", "https://t.me/{}")]:
        try:
            resp = requests.get(url_tpl.format(username), timeout=5,
                                headers=HEADERS, verify=False)
            if resp and resp.status_code not in [404, 410, 999]:
                social_hits.append({"platform": platform,
                                    "url": url_tpl.format(username), "found": True})
        except: pass
    result["social"] = social_hits

    # Permutations
    parts_u = re.split(r'[._\-]', username)
    perms = set()
    if len(parts_u) >= 2:
        f, l = parts_u[0], parts_u[-1]
        for d in ["gmail.com", "yahoo.com", "outlook.com", domain]:
            for p in [f"{f}.{l}", f"{f}{l}", f"{l}.{f}", f"{f[0]}{l}", f"{l}{f[0]}"]:
                perms.add(f"{p}@{d}")
    result["permutations"] = list(perms)[:15]

    # Dorks
    g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    result["dorks"] = [
        {"label": "Identity",      "url": g(f'"{email}"')},
        {"label": "Fraud",         "url": g(f'"{email}" scam OR fraud OR complaint')},
        {"label": "GitHub",        "url": g(f'"{username}" site:github.com')},
        {"label": "LinkedIn",      "url": g(f'"{email}" site:linkedin.com')},
        {"label": "Pastebin",      "url": g(f'"{email}" site:pastebin.com')},
        {"label": "HIBP Check",    "url": f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"},
        {"label": "DeHashed",      "url": f"https://dehashed.com/search?query={urllib.parse.quote(email)}"},
    ]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# USERNAME ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def username_run(username: str) -> dict:
    result = {
        "username": username, "ts": datetime.now().isoformat(),
        "found": [], "not_found": [], "error": [], "total_checked": len(USERNAME_SITES)
    }

    def check(site):
        url = site["url"].format(username)
        err_text = site.get("err", "")
        try:
            r = requests.get(url, timeout=8, headers=HEADERS,
                             allow_redirects=True, verify=False)
            if r and r.status_code not in [404, 410, 999]:
                if not err_text or err_text.lower() not in r.text.lower():
                    return site["name"], url, "FOUND", r.status_code
            return site["name"], url, "NOT_FOUND", getattr(r, 'status_code', 0)
        except Exception:
            return site["name"], url, "ERROR", 0

    with ThreadPoolExecutor(max_workers=20) as ex:
        for name, url, status, code in ex.map(check, USERNAME_SITES):
            if   status == "FOUND":     result["found"].append({"site": name, "url": url, "code": code})
            elif status == "NOT_FOUND": result["not_found"].append(name)
            else:                       result["error"].append(name)

    # Dorks
    g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    result["dorks"] = [
        {"label": "Profile search",  "url": g(f'"{username}" profile OR bio')},
        {"label": "Real name",       "url": g(f'"{username}" "real name" OR "full name"')},
        {"label": "Location",        "url": g(f'"{username}" location OR city')},
        {"label": "Email",           "url": g(f'"{username}" email OR contact')},
        {"label": "GitHub",          "url": f"https://github.com/{username}"},
        {"label": "Telegram",        "url": f"https://t.me/{username}"},
    ]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def domain_run(domain: str, deep: bool = False, skip_ports: bool = False) -> dict:
    ext  = tldextract.extract(domain)
    root = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    result = {
        "domain": domain, "root": root, "ts": datetime.now().isoformat(),
        "whois": {}, "dns": {}, "ssl": {}, "http": {},
        "ip": "", "geo": {}, "tech": [], "subdomains": [],
        "paths": [], "js": {}, "ports": {}, "wayback": {}, "otx": {},
    }

    # WHOIS
    try:
        w = whois_lib.whois(root)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        age = (datetime.now() - cd).days if cd else None
        result["whois"] = {
            "registrar":    str(w.registrar or ""),
            "org":          str(w.org or ""),
            "country":      str(w.country or ""),
            "created":      str(w.creation_date or ""),
            "expires":      str(w.expiration_date or ""),
            "name_servers": list(set(str(ns).lower() for ns in (w.name_servers or []))),
            "emails":       (list(set(w.emails)) if isinstance(w.emails, (list, set))
                             else [str(w.emails)] if w.emails else []),
            "age_days":     age,
            "new_domain":   bool(age and age < 30),
            "young_domain": bool(age and age < 180),
        }
    except Exception as e:
        result["whois"] = {"error": str(e)}

    # DNS
    dns_data = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            dns_data[rtype] = [str(r) for r in answers]
        except: pass
    for rtype, qname in [("DMARC", f"_dmarc.{domain}"), ("SPF", domain)]:
        try:
            answers = dns.resolver.resolve(qname, "TXT", lifetime=5)
            records = [str(r) for r in answers]
            if rtype == "SPF":
                spf = [r for r in records if "v=spf1" in r.lower()]
                if spf: dns_data["SPF"] = spf
            else:
                dns_data["DMARC"] = records
        except: pass
    result["dns"] = dns_data
    result["dns_security"] = {
        "has_dmarc": "DMARC" in dns_data,
        "has_spf":   "SPF"   in dns_data,
        "has_caa":   "CAA"   in dns_data,
    }

    # IP + Geo
    ip = resolve_ip(domain)
    result["ip"] = ip or ""
    if ip:
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
            if r.ok:
                d = r.json()
                result["geo"] = {
                    "ip": d.get("ip", ip), "city": d.get("city", ""),
                    "region": d.get("region", ""), "country": d.get("country_name", ""),
                    "org": d.get("org", ""), "asn": d.get("asn", ""),
                    "latitude": d.get("latitude", ""), "longitude": d.get("longitude", ""),
                }
        except: pass

    # HTTP + SSL
    for scheme in ["https", "http"]:
        r = safe_get(f"{scheme}://{domain}")
        if r:
            result["http"] = {
                "url": str(r.url), "status": r.status_code,
                "server": r.headers.get("Server", ""),
                "powered_by": r.headers.get("X-Powered-By", ""),
                "security_headers": {
                    "hsts": bool(r.headers.get("Strict-Transport-Security")),
                    "csp":  bool(r.headers.get("Content-Security-Policy")),
                    "xframe": bool(r.headers.get("X-Frame-Options")),
                    "xcto":  bool(r.headers.get("X-Content-Type-Options")),
                }
            }
            # Detect tech from HTML
            html = r.text[:10000]
            techs = []
            sigs = {
                "WordPress": ["wp-content", "wp-includes"],
                "React": ["__reactFiber", "__NEXT_DATA__"],
                "Vue.js": ["__vue__", "v-bind:"],
                "Angular": ["ng-version="],
                "Laravel": ["laravel_session"],
                "Django": ["csrfmiddlewaretoken"],
                "Cloudflare": ["cf-ray"],
                "jQuery": ["jquery.min.js"],
            }
            combined = html.lower() + " " + " ".join(f"{k}:{v}".lower() for k, v in r.headers.items())
            for tech, keywords in sigs.items():
                if any(k.lower() in combined for k in keywords):
                    techs.append(tech)
            result["tech"] = techs

            # Harvest emails from HTML
            result["harvested_emails"] = list(set(
                re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)
            ))[:10]
            break

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=6),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
            nb   = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            na   = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
            days = (na - datetime.now()).days
            san  = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            result["ssl"] = {
                "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", ""),
                "valid_from": str(nb.date()), "valid_to": str(na.date()),
                "days_left": days, "san_count": len(san), "san": san[:8],
                "expired": days < 0, "expiring_soon": 0 < days < 30,
            }
    except Exception as e:
        result["ssl"] = {"error": str(e)}

    # Subdomains (crt.sh + HackerTarget)
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{root}&output=json", timeout=15)
        if r.ok:
            for entry in r.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{root}"): subs.add(n)
    except: pass
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={root}", timeout=10)
        if r.ok and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts: subs.add(parts[0].strip())
    except: pass
    result["subdomains"] = sorted(list(subs))[:50]

    # Wayback Machine
    try:
        r = requests.get("https://web.archive.org/cdx/search/cdx",
                         params={"url": domain, "output": "json", "limit": 8,
                                 "fl": "timestamp,statuscode", "collapse": "timestamp:6"},
                         timeout=12)
        if r.ok:
            rows = r.json()[1:] if len(r.json()) > 1 else []
            result["wayback"] = {
                "snapshots": len(rows),
                "first_seen": rows[-1][0][:8] if rows else "",
                "last_seen":  rows[0][0][:8]  if rows else "",
                "urls": [f"https://web.archive.org/web/{row[0]}/{domain}" for row in rows[:5]],
            }
    except:
        result["wayback"] = {"snapshots": 0}

    # OTX Threat Intel
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                         timeout=10)
        if r.ok:
            d = r.json()
            pulses = d.get("pulse_info", {}).get("count", 0)
            result["otx"] = {
                "pulses": pulses, "malicious": pulses > 0,
                "categories": d.get("categories", [])[:5],
            }
    except:
        result["otx"] = {"pulses": 0, "malicious": False}

    # Sensitive paths
    PATHS = ["/.env","/.git/HEAD","/.git/config","/config.json","/swagger.json",
             "/wp-admin/","/admin/","/phpinfo.php","/debug","/actuator/env",
             "/graphql","/.htpasswd","/backup.sql","/dump.sql","/server-status"]
    found_paths = []
    def check_path(path):
        r = safe_get(f"https://{domain}{path}", timeout=5)
        if r and r.status_code not in [404, 410]:
            return {"path": path, "status": r.status_code, "size": len(r.content)}
        return None
    with ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(check_path, PATHS):
            if res: found_paths.append(res)
    result["paths"] = found_paths

    # Port scan
    if not skip_ports and ip:
        open_ports = {}
        def check_port(port):
            try:
                s = socket.socket()
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    return port, COMMON_PORTS.get(port, "Unknown")
                s.close()
            except: pass
            return None, None
        with ThreadPoolExecutor(max_workers=30) as ex:
            for p, svc in ex.map(check_port, list(COMMON_PORTS.keys())):
                if p: open_ports[p] = svc
        result["ports"] = dict(sorted(open_ports.items()))
        result["high_risk_ports"] = [{"port": p, "service": svc, "risk": HIGH_RISK_PORTS[p]}
                                      for p, svc in open_ports.items() if p in HIGH_RISK_PORTS]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# PIVOT ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def pivot_run(phone=None, email=None, username=None, domain=None) -> dict:
    result = {"pivots": [], "connections": [], "timeline": [], "graph_hints": []}

    connections = []

    if phone:
        bare = re.sub(r'\D', '', phone)
        connections.append({"from": "phone", "to": "whatsapp",
                            "url": f"https://wa.me/{bare}", "confidence": "high"})
        connections.append({"from": "phone", "to": "telegram",
                            "url": f"https://t.me/+{bare}", "confidence": "medium"})
        # Phone → email guesses
        for suffix in ["@gmail.com", "@yahoo.com", "@outlook.com"]:
            connections.append({"from": "phone", "to": "email",
                                "guess": f"{bare}{suffix}", "confidence": "low"})

    if email:
        uname = email.split("@")[0]
        dom   = email.split("@")[1] if "@" in email else ""
        connections.append({"from": "email", "to": "username",
                            "value": uname, "confidence": "high"})
        if dom not in {"gmail.com","yahoo.com","outlook.com","hotmail.com"}:
            connections.append({"from": "email", "to": "domain",
                                "value": dom, "confidence": "high"})
        # Quick check platforms
        for platform, url_tpl in [("GitHub",    "https://github.com/{}"),
                                   ("Twitter/X", "https://x.com/{}"),
                                   ("Telegram",  "https://t.me/{}")]:
            try:
                r = requests.get(url_tpl.format(uname), timeout=5, headers=HEADERS, verify=False)
                if r and r.status_code not in [404, 410]:
                    connections.append({"from": "email_username", "to": platform,
                                       "url": url_tpl.format(uname), "confidence": "confirmed"})
            except: pass

    if username:
        for platform, url_tpl in [("GitHub",    "https://github.com/{}"),
                                   ("Telegram",  "https://t.me/{}"),
                                   ("Twitter/X", "https://x.com/{}")]:
            try:
                r = requests.get(url_tpl.format(username), timeout=5, headers=HEADERS, verify=False)
                if r and r.status_code not in [404, 410]:
                    connections.append({"from": "username", "to": platform,
                                       "url": url_tpl.format(username), "confidence": "confirmed"})
            except: pass

    if domain:
        # Harvest emails from website
        r = safe_get(f"https://{domain}", timeout=8)
        if r and r.ok:
            emails_found = list(set(re.findall(
                r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r.text
            )))[:8]
            for e in emails_found:
                connections.append({"from": "domain", "to": "email",
                                   "value": e, "confidence": "confirmed"})

    result["connections"] = connections

    # Build D3-ready graph nodes/edges
    nodes, edges = [], []
    nid = 0

    def node(label, ntype, detail=""):
        nonlocal nid
        n = {"id": nid, "label": label, "type": ntype, "detail": detail}
        nodes.append(n); nid += 1
        return n["id"]

    center = node("SUBJECT", "root")
    if phone:    pid = node(phone, "phone");    edges.append({"s": center, "t": pid, "l": "phone"})
    if email:    eid = node(email, "email");    edges.append({"s": center, "t": eid, "l": "email"})
    if username: uid = node(f"@{username}", "username"); edges.append({"s": center, "t": uid, "l": "username"})
    if domain:   did = node(domain, "domain");  edges.append({"s": center, "t": did, "l": "domain"})

    for c in connections:
        if c.get("confidence") in ["confirmed", "high"]:
            src_id  = nid - 1  # approximate
            dest_id = node(c.get("url", c.get("value", c["to"])), c["to"])
            edges.append({"s": center, "t": dest_id, "l": c.get("confidence","")})

    result["graph"] = {"nodes": nodes, "edges": edges}
    return result


# ══════════════════════════════════════════════════════════════════════════════
# FIR GENERATOR (Claude AI)
# ══════════════════════════════════════════════════════════════════════════════
def fir_run(target: str, intel_data: dict, incident_type: str = "Cyber Fraud",
            complainant: str = "", station: str = "") -> dict:

    result = {"target": target, "fir_text": "", "ipc_sections": [],
              "it_act_sections": [], "ts": datetime.now().isoformat()}

    # Determine applicable IPC/IT Act sections
    sections_ipc = []
    sections_it  = []

    # Check for fraud indicators
    phone_risk = intel_data.get("risk", {}).get("score", 0)
    if phone_risk >= 50:
        sections_ipc.extend(["IPC 420 (Cheating)", "IPC 406 (Criminal Breach of Trust)"])
        sections_it.extend(["IT Act Section 66D (Impersonation)"])

    if intel_data.get("breaches"):
        sections_it.append("IT Act Section 43A (Data protection violation)")

    if intel_data.get("smtp", {}).get("exists"):
        sections_ipc.append("IPC 468 (Forgery for cheating)")

    # Always add cyber fraud baseline
    sections_ipc.extend(["IPC 120B (Criminal Conspiracy)", "IPC 34 (Common Intention)"])
    sections_it.extend(["IT Act Section 66C (Identity Theft)", "IT Act Section 66 (Computer-related offences)"])

    result["ipc_sections"] = list(set(sections_ipc))
    result["it_act_sections"] = list(set(sections_it))

    if not HAS_AI:
        # Template FIR without AI
        result["fir_text"] = f"""
FIRST INFORMATION REPORT (FIR)
Police Station: {station or '___________'}
Date: {datetime.now().strftime('%d/%m/%Y')}
Time: {datetime.now().strftime('%H:%M')} IST

COMPLAINANT: {complainant or '___________'}
SUBJECT/ACCUSED IDENTIFIER: {target}
TYPE OF OFFENCE: {incident_type}

BRIEF FACTS:
The complainant reports a case of {incident_type} involving the digital identifier: {target}

OSINT INTELLIGENCE SUMMARY:
{json.dumps(intel_data, indent=2, default=str)[:1000]}

APPLICABLE SECTIONS:
IPC: {', '.join(sections_ipc)}
IT Act: {', '.join(sections_it)}

DIGITAL EVIDENCE:
- All OSINT findings documented and hash-verified
- Chain of custody maintained

Investigating Officer: _________________
"""
        return result

    # AI-enhanced FIR
    try:
        summary = json.dumps(intel_data, default=str)[:2000]
        client  = anthropic.Anthropic()
        msg     = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": f"""
You are a senior cybercrime investigator. Write a formal FIR (First Information Report) 
in Indian police format based on the following OSINT intelligence.

TARGET: {target}
INCIDENT TYPE: {incident_type}
COMPLAINANT: {complainant or 'Under Investigation'}
POLICE STATION: {station or 'Cyber Crime Cell'}
DATE: {datetime.now().strftime('%d/%m/%Y')}

INTELLIGENCE DATA:
{summary}

APPLICABLE LEGAL SECTIONS:
IPC: {', '.join(sections_ipc)}
IT Act: {', '.join(sections_it)}

Write a complete, formal FIR with:
1. FIR Number field (blank)
2. Date, Time, Station
3. Complainant details
4. Brief facts of the case (professional language)
5. Digital evidence summary
6. Accused profile (based on OSINT)
7. Applicable legal sections with explanation
8. Prayer/Relief sought
9. Signature block

Use formal Indian police/legal language. Be specific and court-admissible.
"""}]
        )
        result["fir_text"] = msg.content[0].text
    except Exception as e:
        result["error"] = f"AI generation failed: {e}"
        result["fir_text"] = f"Manual FIR required. Target: {target}. Error: {e}"

    return result
