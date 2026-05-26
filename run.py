#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          OSINT RECON TOOL v2.0 — Cyber Fraud Catcher Edition        ║
║   Domain · Phone · Email · Subdomains · JS · Headers · Ports · AI  ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    python osint_tool.py example.com               # Full domain scan
    python osint_tool.py --phone +919876543210     # Phone intelligence
    python osint_tool.py --email target@gmail.com  # Email intelligence
    python osint_tool.py --username johndoe        # Username hunt
    python osint_tool.py example.com --deep        # Deep scan mode
    python osint_tool.py --help                    # Show all options
"""

import sys, json, re, socket, ssl, time, argparse, hashlib, urllib.parse
import os, csv, ipaddress
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── core libs ────────────────────────────────────────────────────────────────
import requests, httpx, dns.resolver, dns.zone, dns.query
import whois as whois_lib, tldextract
from bs4 import BeautifulSoup
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.tree import Tree
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.live import Live
from rich.layout import Layout
from rich.align import Align

# optional
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    PHONE_LIB = True
except ImportError:
    PHONE_LIB = False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console(highlight=True)

# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════
BANNER = """[bold cyan]
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ██╗   ██╗██████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██║   ██║╚════██╗
██║   ██║███████╗██║██╔██╗ ██║   ██║       ██║   ██║ █████╔╝
██║   ██║╚════██║██║██║╚██╗██║   ██║       ╚██╗ ██╔╝██╔═══╝
╚██████╔╝███████║██║██║ ╚████║   ██║        ╚████╔╝ ███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝         ╚═══╝  ╚══════╝
[/bold cyan][bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]
[bold white]   Cyber Fraud Catcher Edition  |  Domain · Phone · Email · Username
[/bold white][bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]
"""

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS / CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
HEADERS_UA = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com",
    "throwam.com","yopmail.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","spam4.me","trashmail.com","dispostable.com","mailnull.com",
    "spamgourmet.com","fakeinbox.com","maildrop.cc","temp-mail.org",
    "discard.email","spamhereplease.com","emailondeck.com","mintemail.com",
    "throwaway.email","moakt.com","anonbox.net","spambox.us",
}

SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":    r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":      r"[a-z0-9-]+\.firebaseio\.com",
    "Firebase Config":   r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Stripe Live":       r"sk_live_[a-zA-Z0-9]{24,}",
    "Stripe Public":     r"pk_live_[a-zA-Z0-9]{24,}",
    "Stripe Test":       r"sk_test_[a-zA-Z0-9]{24,}",
    "GitHub PAT":        r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth":      r"gho_[a-zA-Z0-9]{36}",
    "GitHub App Token":  r"github_pat_[a-zA-Z0-9_]{82}",
    "Slack Token":       r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook":     r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,}",
    "Discord Token":     r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27}",
    "Discord Webhook":   r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "Twilio SID":        r"AC[a-z0-9]{32}",
    "Twilio Token":      r"SK[0-9a-fA-F]{32}",
    "SendGrid Key":      r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun Key":       r"key-[0-9a-zA-Z]{32}",
    "JWT Token":         r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
    "SSH Private Key":   r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "PGP Private Key":   r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Password":  r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Generic Secret":    r"(?i)(?:secret|api_?key|auth_?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "PayPal/Braintree":  r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Cloudinary":        r"cloudinary://[0-9]{15}:[A-Za-z0-9_\-]{27}@[a-z]+",
    "Heroku API Key":    r"[hH]eroku[^\w]*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Phone Number (IN)": r"(?<!\d)(?:\+91|0)?[6-9]\d{9}(?!\d)",
    "Email Address":     r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "IP Address":        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "Base64 Blob":       r"(?:[A-Za-z0-9+/]{40,}={0,2})",
}

COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","dev","staging",
    "test","api","app","mobile","m","admin","dashboard","portal","blog","shop",
    "store","cdn","media","assets","static","img","images","video","news",
    "support","help","docs","wiki","forum","community","beta","alpha","old",
    "new","v2","v3","vpn","gateway","proxy","secure","login","auth","sso",
    "id","account","accounts","my","cloud","files","backup","db","database",
    "sql","mongo","redis","cache","search","analytics","tracking","metrics",
    "monitor","status","health","ping","internal","corp","intranet","office",
    "hr","finance","sales","marketing","api2","api3","stage","uat","prod",
    "preprod","sandbox","demo","preview","web","web2","web3","mail2","ns1",
    "ns2","mx","mx1","smtp2","autodiscover","autoconfig","cpanel","whm",
    "plesk","ftp2","sftp","ssh","git","svn","jenkins","ci","jira","confluence",
    "grafana","kibana","elastic","mongo","mysql","redis","memcached","rabbitmq",
]

INTERESTING_PATHS = [
    "/.env","/.env.local","/.env.production","/.env.backup","/.env.dev",
    "/.env.example","/.env.sample","/.env.test","/.env.staging",
    "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG","/.gitignore",
    "/.htaccess","/.htpasswd","/.htpasswd_test",
    "/config.json","/config.yaml","/config.yml","/settings.json",
    "/settings.py","/config.php","/configuration.php",
    "/swagger.json","/swagger.yaml","/openapi.json","/openapi.yaml",
    "/api-docs","/api/v1/docs","/api/v2/docs","/api/swagger",
    "/graphql","/graphiql","/__graphql","/graphql/playground",
    "/robots.txt","/sitemap.xml","/sitemap_index.xml","/security.txt",
    "/.well-known/security.txt","/.well-known/jwks.json",
    "/manifest.json","/package.json","/composer.json","/Gemfile",
    "/wp-admin/","/wp-login.php","/wp-config.php","/wp-json/wp/v2/users",
    "/admin/","/administrator/","/login","/dashboard","/panel",
    "/backup.zip","/backup.sql","/dump.sql","/database.sql","/db.sql",
    "/debug","/phpinfo.php","/info.php","/test.php","/_debug",
    "/server-status","/server-info","/.DS_Store","/_profiler",
    "/api/v1/users","/api/v1/admin","/v1/health","/health",
    "/status","/ping","/_ah/health","/actuator","/actuator/health",
    "/actuator/env","/actuator/mappings","/actuator/beans",
    "/metrics","/prometheus","/trace","/logfile",
    "/console","/h2-console","/jolokia","/druid",
    "/.idea/workspace.xml","/.vscode/settings.json",
    "/crossdomain.xml","/clientaccesspolicy.xml",
    "/upload","/uploads","/file","/files","/media",
    "/download","/downloads","/temp","/tmp",
    "/static/admin","/assets/admin",
    "/source.map","/app.js.map","/main.js.map","/bundle.js.map",
    "/__webpack_hmr","/.webpack",
    "/rails/info/properties","/rails/mailers",
    "/telescope","/horizon","/nova","/sanctum/csrf-cookie",
]

CMS_SIGNATURES = {
    "WordPress":      ["/wp-content/","/wp-includes/","wp-json","xmlrpc.php","wp-cron"],
    "Drupal":         ["/sites/default/","Drupal.settings","drupal.js","X-Generator: Drupal"],
    "Joomla":         ["/components/com_","/modules/mod_","Joomla!","joomla"],
    "Shopify":        ["cdn.shopify.com","Shopify.theme","myshopify.com"],
    "Wix":            ["wix.com","_wix_browser_","wixsite.com"],
    "Squarespace":    ["squarespace.com","static.squarespace.com","squarespace-cdn"],
    "Webflow":        ["webflow.com","wf-form","webflow"],
    "Ghost":          ["/ghost/api/","ghost.io","content/themes/ghost"],
    "Next.js":        ["/_next/","__NEXT_DATA__","_next/static"],
    "Nuxt.js":        ["/_nuxt/","__NUXT__","nuxt"],
    "React":          ["react.development.js","react.production.min.js","_reactFiber","__reactFiber"],
    "Vue.js":         ["vue.runtime.min.js","__vue__","v-bind:","vue.min.js"],
    "Angular":        ["ng-version=","angular.min.js","ng-app","angular/core"],
    "Svelte":         ["__SVELTEKIT","svelte","kit.svelte"],
    "Laravel":        ["laravel_session","XSRF-TOKEN","laravel"],
    "Django":         ["csrfmiddlewaretoken","django","Set-Cookie: csrftoken"],
    "Rails":          ["_rails-root","X-Request-Id","ActionController","_session_id"],
    "Express.js":     ["X-Powered-By: Express","express"],
    "Spring Boot":    ["X-Application-Context","spring","springframework"],
    "ASP.NET":        ["X-Powered-By: ASP.NET","__VIEWSTATE","ASPNET_SessionId"],
    "PHP":            ["X-Powered-By: PHP","PHPSESSID"],
    "Nginx":          ["nginx"],
    "Apache":         ["Apache","mod_"],
    "IIS":            ["Microsoft-IIS","X-Powered-By: ASP"],
    "Cloudflare":     ["cf-ray","__cfduid","cloudflare","CF-Cache-Status"],
    "AWS CloudFront": ["X-Cache: Hit from cloudfront","X-Amz-Cf-Id","CloudFront"],
    "Vercel":         ["x-vercel-id","vercel.com","X-Vercel-Cache"],
    "Netlify":        ["x-nf-request-id","netlify","X-Nf-Request-Id"],
    "Heroku":         ["heroku.com","herokuapp.com","X-Heroku"],
    "Firebase":       ["firebaseapp.com","firebaseio.com","firebase"],
    "Supabase":       ["supabase.co","supabase.io"],
    "Fastly":         ["fastly.net","X-Fastly-Request-Id","Via: 1.1 varnish"],
    "Akamai":         ["X-Akamai-Transformed","akamaiedge.net","akamaitech"],
    "Google Fonts":   ["fonts.googleapis.com"],
    "Bootstrap":      ["bootstrap.min.css","bootstrap.min.js","getbootstrap"],
    "jQuery":         ["jquery.min.js","jquery.js","jquery-"],
    "Tailwind CSS":   ["tailwind","tailwindcss"],
    "Google Analytics":["google-analytics.com","ga('create'","gtag("],
    "Facebook Pixel": ["connect.facebook.net","fbq(","facebook.com/tr"],
    "HubSpot":        ["hs-analytics","hubspot.com","_hsq"],
    "Intercom":       ["intercom.io","intercom-"],
    "Zendesk":        ["zendesk.com","zEu","zopim"],
    "Stripe":         ["js.stripe.com","stripe.js","Stripe("],
    "PayPal":         ["paypal.com/sdk","paypalcdn"],
    "reCAPTCHA":      ["recaptcha/api.js","g-recaptcha"],
}

CLOUD_SIGS = {
    "Cloudflare":    ["cloudflare.com","cf-ray","cloudflare","CF-Cache"],
    "AWS":           ["amazonaws.com","aws-cf","x-amz","cloudfront.net"],
    "Azure":         ["azurewebsites.net","azure.com","x-ms-","windows.net"],
    "GCP":           ["googleapis.com","googlecloud","x-cloud-trace-context","appspot.com"],
    "Vercel":        ["vercel.com","x-vercel-id",".vercel.app","vercel"],
    "Netlify":       ["netlify.com","x-nf-request-id",".netlify.app","netlify"],
    "Fastly":        ["fastly.net","x-fastly","via: varnish"],
    "Akamai":        ["akamai.com","x-akamai","akamaiedge"],
    "DigitalOcean":  ["digitalocean.com","do-app",".ondigitalocean.app"],
    "Heroku":        ["heroku.com","herokuapp.com"],
    "Linode":        ["linode.com","linodeobjects"],
    "Vultr":         ["vultr.com"],
    "OVH":           ["ovh.com","ovh.net"],
    "Hetzner":       ["hetzner.com","hetzner.de"],
    "Firebase":      ["firebaseapp.com","firebaseio.com"],
    "Supabase":      ["supabase.co","supabase.io"],
    "Railway":       ["railway.app"],
    "Render":        ["onrender.com"],
    "Fly.io":        ["fly.dev","fly.io"],
}

USERNAME_SITES = [
    {"name":"GitHub",        "url":"https://github.com/{}",            "err":"Not Found"},
    {"name":"Twitter/X",     "url":"https://x.com/{}",                 "err":"This account doesn't exist"},
    {"name":"Instagram",     "url":"https://www.instagram.com/{}/",    "err":"Sorry, this page isn't available"},
    {"name":"Reddit",        "url":"https://www.reddit.com/user/{}",   "err":"Sorry, nobody on Reddit goes by that name"},
    {"name":"LinkedIn",      "url":"https://www.linkedin.com/in/{}",   "err":"Page not found"},
    {"name":"TikTok",        "url":"https://www.tiktok.com/@{}",       "err":"Couldn't find this account"},
    {"name":"YouTube",       "url":"https://www.youtube.com/@{}",      "err":"This page isn't available"},
    {"name":"Pinterest",     "url":"https://www.pinterest.com/{}/",    "err":"Sorry! We couldn't find that page"},
    {"name":"Telegram",      "url":"https://t.me/{}",                  "err":"If you have Telegram"},
    {"name":"Steam",         "url":"https://steamcommunity.com/id/{}", "err":"The specified profile could not be found"},
    {"name":"Twitch",        "url":"https://www.twitch.tv/{}",         "err":"Sorry. Unless you've got a time machine"},
    {"name":"Medium",        "url":"https://medium.com/@{}",           "err":"Page not found"},
    {"name":"Dev.to",        "url":"https://dev.to/{}",                "err":"404"},
    {"name":"Hashnode",      "url":"https://hashnode.com/@{}",         "err":"Oops! We can't find what you were looking for"},
    {"name":"HackerNews",    "url":"https://news.ycombinator.com/user?id={}","err":"No such user"},
    {"name":"GitLab",        "url":"https://gitlab.com/{}",            "err":"404"},
    {"name":"Bitbucket",     "url":"https://bitbucket.org/{}",         "err":"Page Not Found"},
    {"name":"Keybase",       "url":"https://keybase.io/{}",            "err":"404"},
    {"name":"Pastebin",      "url":"https://pastebin.com/u/{}",        "err":"Not Found"},
    {"name":"Replit",        "url":"https://replit.com/@{}",           "err":"Page not found"},
    {"name":"Product Hunt",  "url":"https://www.producthunt.com/@{}",  "err":"404"},
    {"name":"AngelList",     "url":"https://angel.co/u/{}",            "err":"404"},
    {"name":"Gravatar",      "url":"https://en.gravatar.com/{}",       "err":"We couldn't find that user"},
    {"name":"Fiverr",        "url":"https://www.fiverr.com/{}",        "err":"404"},
    {"name":"Upwork",        "url":"https://www.upwork.com/freelancers/~{}","err":"No Profile"},
    {"name":"HackerRank",    "url":"https://www.hackerrank.com/{}",    "err":"Page Not Found"},
    {"name":"LeetCode",      "url":"https://leetcode.com/{}",          "err":"does not exist"},
    {"name":"CodePen",       "url":"https://codepen.io/{}",            "err":"404"},
    {"name":"NPM",           "url":"https://www.npmjs.com/~{}",        "err":"404"},
    {"name":"PyPI",          "url":"https://pypi.org/user/{}",         "err":"404"},
    {"name":"DockerHub",     "url":"https://hub.docker.com/u/{}",      "err":"404"},
    {"name":"Behance",       "url":"https://www.behance.net/{}",       "err":"This page is not available"},
    {"name":"Dribbble",      "url":"https://dribbble.com/{}",          "err":"Whoops, that page is gone"},
    {"name":"Vimeo",         "url":"https://vimeo.com/{}",             "err":"Sorry, we couldn't find that page"},
    {"name":"SoundCloud",    "url":"https://soundcloud.com/{}",        "err":"We can't find that user"},
    {"name":"Spotify",       "url":"https://open.spotify.com/user/{}","err":"Page not found"},
    {"name":"Last.fm",       "url":"https://www.last.fm/user/{}",      "err":"Page Not Found"},
    {"name":"Xbox",          "url":"https://xboxgamertag.com/search/{}", "err":"No results"},
    {"name":"About.me",      "url":"https://about.me/{}",              "err":"404"},
    {"name":"Flipboard",     "url":"https://flipboard.com/@{}",        "err":"Page Not Found"},
]

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    69:"TFTP", 80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC",
    137:"NetBIOS", 139:"NetBIOS-SMB", 143:"IMAP", 389:"LDAP",
    443:"HTTPS", 445:"SMB", 465:"SMTPS", 587:"SMTP-TLS",
    631:"IPP", 993:"IMAPS", 995:"POP3S", 1433:"MSSQL",
    1521:"Oracle", 1723:"PPTP", 2082:"cPanel", 2083:"cPanel-SSL",
    2086:"WHM", 2087:"WHM-SSL", 2375:"Docker", 2376:"Docker-TLS",
    3000:"Dev-Server", 3306:"MySQL", 3389:"RDP", 3690:"SVN",
    4443:"HTTPS-Alt", 5000:"Flask/Dev", 5432:"PostgreSQL",
    5900:"VNC", 5984:"CouchDB", 6379:"Redis",
    7001:"WebLogic", 7474:"Neo4j", 8000:"Dev", 8080:"HTTP-Alt",
    8086:"InfluxDB", 8088:"HTTP-Alt2", 8443:"HTTPS-Alt",
    8888:"Jupyter", 9000:"PHP-FPM/SonarQube", 9090:"Prometheus",
    9092:"Kafka", 9200:"Elasticsearch", 9300:"Elasticsearch-Cluster",
    11211:"Memcached", 27017:"MongoDB", 27018:"MongoDB-Alt",
    50000:"SAP", 50070:"Hadoop", 61616:"ActiveMQ",
}

HIGH_RISK_PORTS = {
    23:"⚠ TELNET — Unencrypted remote access!",
    21:"⚠ FTP — Unencrypted file transfer!",
    3389:"⚠ RDP EXPOSED — Remote Desktop vulnerable!",
    6379:"⚠ REDIS EXPOSED — Often no auth!",
    27017:"⚠ MONGODB EXPOSED — Often no auth!",
    9200:"⚠ ELASTICSEARCH EXPOSED — Data breach risk!",
    5984:"⚠ COUCHDB EXPOSED!",
    11211:"⚠ MEMCACHED EXPOSED!",
    2375:"⚠ DOCKER API EXPOSED — Critical!",
    5900:"⚠ VNC EXPOSED — Remote screen!",
    2082:"⚠ cPanel EXPOSED!",
    445:"⚠ SMB EXPOSED — EternalBlue risk!",
    139:"⚠ NetBIOS EXPOSED!",
    1433:"⚠ MSSQL EXPOSED!",
    5432:"⚠ PostgreSQL EXPOSED!",
    3306:"⚠ MySQL EXPOSED!",
    8888:"⚠ Jupyter Notebook — Often no auth!",
    50070:"⚠ Hadoop Admin EXPOSED!",
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════
def safe_get(url, timeout=10, allow_redirects=True, verify=False):
    try:
        return requests.get(url, timeout=timeout, headers=HEADERS_UA,
                            allow_redirects=allow_redirects, verify=verify)
    except Exception:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def status_badge(code):
    if code < 300:   return f"[bold green]{code}[/bold green]"
    if code < 400:   return f"[bold yellow]{code}[/bold yellow]"
    if code < 500:   return f"[bold red]{code}[/bold red]"
    return f"[dim]{code}[/dim]"

def safe_slug(text):
    """Convert any string to a safe directory name."""
    text = re.sub(r'https?://', '', text)
    text = re.sub(r'[^\w\-]', '_', text)
    return text.strip('_')[:80]

def section(title):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))

def ok(msg):  console.print(f"  [bold green]✓[/bold green] {msg}")
def warn(msg): console.print(f"  [bold yellow]⚠[/bold yellow] {msg}")
def err(msg):  console.print(f"  [bold red]✗[/bold red] {msg}")
def info(msg): console.print(f"  [cyan]→[/cyan] {msg}")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — WHOIS
# ═══════════════════════════════════════════════════════════════════════════════
def run_whois(domain):
    try:
        w = whois_lib.whois(domain)
        data = {
            "registrar":       str(w.registrar or ""),
            "creation_date":   str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "updated_date":    str(w.updated_date or ""),
            "name_servers":    list(set(str(ns).lower() for ns in (w.name_servers or []))),
            "status":          str(w.status or ""),
            "emails":          (list(set(w.emails)) if isinstance(w.emails,(list,set))
                                else [str(w.emails)] if w.emails else []),
            "org":             str(w.org or ""),
            "country":         str(w.country or ""),
            "dnssec":          str(getattr(w,'dnssec','') or ""),
        }
        # Domain age
        try:
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd:
                age = (datetime.now() - cd).days
                data["domain_age_days"] = age
                if age < 30:
                    data["NEW_DOMAIN_WARNING"] = True
        except Exception:
            pass
        return data
    except Exception as e:
        return {"error": str(e)}

def print_whois(data):
    section("WHOIS Intelligence")
    if "error" in data:
        err(f"WHOIS failed: {data['error']}")
        return
    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
    t.add_column("Field", style="bold cyan", width=22)
    t.add_column("Value", style="white")
    rows = [
        ("Registrar",        data.get("registrar","")),
        ("Org",              data.get("org","")),
        ("Country",          data.get("country","")),
        ("Created",          data.get("creation_date","")),
        ("Expires",          data.get("expiration_date","")),
        ("Updated",          data.get("updated_date","")),
        ("DNSSEC",           data.get("dnssec","")),
        ("Name Servers",     "\n".join(data.get("name_servers",[]))),
        ("WHOIS Emails",     "\n".join(data.get("emails",[]))),
    ]
    for k,v in rows:
        if v and v not in ("None","[]"):
            t.add_row(k, str(v)[:120])
    console.print(t)
    age = data.get("domain_age_days")
    if age is not None:
        if data.get("NEW_DOMAIN_WARNING"):
            warn(f"[bold red]🚨 NEWLY REGISTERED DOMAIN! Only {age} days old — HIGH FRAUD RISK[/bold red]")
        else:
            info(f"Domain age: {age} days ({age//365} years)")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — DNS
# ═══════════════════════════════════════════════════════════════════════════════
def run_dns(domain):
    results = {}
    for rtype in ["A","AAAA","MX","TXT","NS","CNAME","SOA","CAA","SRV","PTR","DMARC","DKIM"]:
        try:
            qname = domain
            if rtype == "DMARC": qname = f"_dmarc.{domain}"; rtype_q = "TXT"
            elif rtype == "DKIM": qname = f"default._domainkey.{domain}"; rtype_q = "TXT"
            else: rtype_q = rtype
            answers = dns.resolver.resolve(qname, rtype_q, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    # SPF analysis
    for txt in results.get("TXT",[]):
        if "v=spf1" in txt.lower():
            results["SPF"] = [txt]
    return results

def print_dns(data, domain):
    section("DNS Intelligence")
    if not data:
        warn("No DNS records resolved")
        return
    tree = Tree(f"[bold cyan]🌐  {domain}[/bold cyan]")
    icons = {"A":"📍","AAAA":"📍","MX":"📧","TXT":"📝","NS":"🔑","CNAME":"🔗",
             "SOA":"📋","CAA":"🔒","SRV":"⚙","DMARC":"🛡","DKIM":"🔐","SPF":"📮"}
    for rtype, records in data.items():
        branch = tree.add(f"[bold yellow]{icons.get(rtype,'•')} {rtype}[/bold yellow]")
        for r in records:
            branch.add(f"[white]{r[:120]}[/white]")
    console.print(tree)
    # Security checks
    if "DMARC" not in data: warn("No DMARC record — Email spoofing possible!")
    if "SPF"   not in data: warn("No SPF record — Email spoofing possible!")
    if "CAA"   not in data: warn("No CAA record — Any CA can issue certs for this domain!")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — HTTP HEADERS + SSL
# ═══════════════════════════════════════════════════════════════════════════════
def run_headers(domain):
    for scheme in ["https","http"]:
        url = f"{scheme}://{domain}"
        r = safe_get(url, allow_redirects=True)
        if r:
            return {
                "url":        url, "status": r.status_code,
                "headers":    dict(r.headers), "server": r.headers.get("Server",""),
                "powered_by": r.headers.get("X-Powered-By",""),
                "final_url":  r.url, "encoding": r.encoding or "",
            }
    return {}

def run_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain,443),timeout=8),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
            san  = [v for k,v in cert.get("subjectAltName",[]) if k=="DNS"]
            nb   = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            na   = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
            days_left = (na - datetime.now()).days
            return {
                "subject":    dict(x[0] for x in cert.get("subject",[])),
                "issuer":     dict(x[0] for x in cert.get("issuer",[])),
                "not_before": str(nb.date()), "not_after": str(na.date()),
                "days_left":  days_left, "san": san, "san_count": len(san),
                "version":    cert.get("version",""),
                "self_signed": cert.get("issuer") == cert.get("subject"),
                "expired":    days_left < 0,
                "expiring_soon": 0 < days_left < 30,
            }
    except Exception as e:
        return {"error": str(e)}

def run_security_headers(headers):
    checks = {
        "Strict-Transport-Security":         ("HSTS",            "red",    "Enables HTTPS enforcement"),
        "Content-Security-Policy":           ("CSP",             "red",    "Prevents XSS & injection"),
        "X-Frame-Options":                   ("Anti-Clickjack",  "yellow", "Prevents iframe embedding"),
        "X-Content-Type-Options":            ("MIME-Sniff Block","yellow", "Prevents MIME sniffing"),
        "Referrer-Policy":                   ("Referrer Policy", "blue",   "Controls referrer leaking"),
        "Permissions-Policy":                ("Permissions",     "blue",   "Controls browser features"),
        "Cross-Origin-Opener-Policy":        ("COOP",            "blue",   "Isolates browsing context"),
        "Cross-Origin-Resource-Policy":      ("CORP",            "blue",   "Prevents cross-origin reads"),
        "Cross-Origin-Embedder-Policy":      ("COEP",            "blue",   "Controls embedders"),
        "X-XSS-Protection":                  ("XSS Filter",      "dim",    "Legacy XSS filter"),
    }
    h_lower = {k.lower():v for k,v in headers.items()}
    results = {}
    for header,(label,sev,desc) in checks.items():
        present = header.lower() in h_lower
        results[label] = {
            "header":  header, "present": present,
            "value":   h_lower.get(header.lower(),""),
            "severity":sev, "desc": desc,
        }
    return results

def print_headers_ssl(hdr, ssl_d, sec):
    section("HTTP / TLS Fingerprint")
    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
    t.add_column("Key",style="bold cyan",width=16); t.add_column("Value")
    t.add_row("URL",     hdr.get("url",""))
    t.add_row("Status",  str(hdr.get("status","")))
    t.add_row("Server",  hdr.get("server","[dim]—[/dim]"))
    t.add_row("Powered", hdr.get("powered_by","[dim]—[/dim]"))
    t.add_row("Encoding",hdr.get("encoding","[dim]—[/dim]"))
    console.print(t)

    if ssl_d and "error" not in ssl_d:
        console.print()
        console.print("[bold yellow]🔒 TLS Certificate[/bold yellow]")
        ts = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
        ts.add_column("Key",style="bold cyan",width=16); ts.add_column("Value")
        issuer = ssl_d.get("issuer",{})
        ts.add_row("Issuer",      issuer.get("organizationName", issuer.get("commonName","")))
        ts.add_row("Valid From",  ssl_d.get("not_before",""))
        ts.add_row("Expires",     ssl_d.get("not_after",""))
        days   = ssl_d.get("days_left",0)
        day_s  = (f"[bold red]{days} days — EXPIRED![/bold red]" if days < 0 else
                  f"[bold yellow]{days} days — EXPIRING SOON[/bold yellow]" if days < 30
                  else f"[green]{days} days[/green]")
        ts.add_row("Days Left",   day_s)
        ts.add_row("SAN Count",   str(ssl_d.get("san_count",0)))
        san = ssl_d.get("san",[])
        if san: ts.add_row("SANs", ", ".join(san[:6]) + ("…" if len(san)>6 else ""))
        if ssl_d.get("self_signed"): ts.add_row("⚠ WARNING","SELF-SIGNED CERTIFICATE!")
        console.print(ts)
    elif ssl_d and "error" in ssl_d:
        err(f"SSL failed: {ssl_d['error']}")

    console.print()
    console.print("[bold yellow]🛡  Security Headers[/bold yellow]")
    sh = Table(box=box.SIMPLE, padding=(0,1))
    sh.add_column("Header",  style="bold", width=18)
    sh.add_column("Status",  width=14)
    sh.add_column("Notes",   style="dim")
    for label,info_d in sec.items():
        badge = "[bold green]✓ SET[/bold green]" if info_d["present"] else f"[bold {info_d['severity']}]✗ MISSING[/bold {info_d['severity']}]"
        sh.add_row(label, badge, info_d["desc"])
    console.print(sh)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — TECH STACK
# ═══════════════════════════════════════════════════════════════════════════════
def detect_tech(domain, headers, html):
    combined = html.lower() + " " + " ".join(f"{k}:{v}".lower() for k,v in headers.items())
    detected = []
    for tech, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined:
                detected.append(tech); break
    return sorted(set(detected))

def detect_cloud(domain, headers, dns_data):
    combined = domain.lower()
    for k,v in headers.items(): combined += f" {k.lower()}:{v.lower()}"
    for records in dns_data.values():
        for r in records: combined += f" {r.lower()}"
    detected = []
    for provider, sigs in CLOUD_SIGS.items():
        for sig in sigs:
            if sig.lower() in combined:
                detected.append(provider); break
    return list(set(detected))

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — SUBDOMAINS
# ═══════════════════════════════════════════════════════════════════════════════
def crtsh_subdomains(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r.ok:
            for entry in r.json():
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain:
                        subs.add(n)
    except Exception:
        pass
    return sorted(subs)

def hackertarget_subdomains(domain):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.ok and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts: subs.add(parts[0].strip())
    except Exception:
        pass
    return sorted(subs)

def bruteforce_subdomains(domain, wordlist):
    found = []
    def check(sub):
        fqdn = f"{sub}.{domain}"
        ip = resolve_ip(fqdn)
        return (fqdn, ip) if ip else (None, None)
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check,s):s for s in wordlist}
        for f in as_completed(futures):
            fqdn, ip = f.result()
            if fqdn: found.append((fqdn, ip))
    return sorted(found)

def print_subdomains(passive, brute):
    section("Subdomain Intelligence")
    all_subs = dict()
    for s in passive: all_subs[s] = {"ip": resolve_ip(s) or "", "source": "passive"}
    for fqdn, ip in brute:
        if fqdn not in all_subs: all_subs[fqdn] = {"ip": ip, "source": "brute"}
        else: all_subs[fqdn]["source"] += "+brute"
    if not all_subs:
        warn("No subdomains discovered"); return
    t = Table(box=box.SIMPLE, padding=(0,1))
    t.add_column("Subdomain", style="bold white")
    t.add_column("IP",        style="cyan",   width=18)
    t.add_column("Source",    style="dim",    width=14)
    for sub, meta in sorted(all_subs.items()):
        src_s = ""
        if "passive" in meta["source"]:   src_s += "[green]cert[/green] "
        if "brute"   in meta["source"]:   src_s += "[yellow]brute[/yellow]"
        t.add_row(sub, meta["ip"], src_s)
    console.print(t)
    ok(f"Total: {len(all_subs)} subdomains found")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — PATH DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
def run_path_discovery(base_url, paths):
    found = []
    def check(path):
        url = base_url.rstrip("/") + path
        r = safe_get(url, timeout=6)
        if r and r.status_code not in [404, 410]:
            return {"url":url,"status":r.status_code,"size":len(r.content),"path":path}
        return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check,p):p for p in paths}
        for f in as_completed(futures):
            result = f.result()
            if result: found.append(result)
    return sorted(found, key=lambda x: x["status"])

def print_paths(found):
    section("Path & File Discovery")
    if not found: warn("No interesting paths found"); return
    t = Table(box=box.SIMPLE, padding=(0,1))
    t.add_column("Status", width=8)
    t.add_column("Size",   style="dim", width=10)
    t.add_column("Path",   style="bold white")
    t.add_column("Risk",   style="bold red")
    high_risk = {".env","git","config","backup","sql","dump","swagger","phpinfo","admin","debug"}
    for item in found:
        risk = "🚨 CRITICAL" if any(x in item["path"].lower() for x in high_risk) else ""
        t.add_row(status_badge(item["status"]), f"{item['size']:,}b", item["path"], risk)
    console.print(t)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7 — JS RECON
# ═══════════════════════════════════════════════════════════════════════════════
def extract_js_endpoints(js):
    pats = [
        r'["\'](/api/[a-zA-Z0-9_/.\-]+)["\']',
        r'["\'](https?://[a-zA-Z0-9._/\-?=&%]+)["\']',
        r'url\s*:\s*["\']([^"\']{5,150})["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'["\'](/v\d+/[a-zA-Z0-9_/.\-]+)["\']',
        r'endpoint["\'\s:=]+["\']([^"\']{5,150})["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
        r'path\s*:\s*["\'](/[a-zA-Z0-9_/.\-]+)["\']',
        r'href\s*[=:]\s*["\']([^"\']{5,})["\']',
    ]
    endpoints = set()
    for pat in pats:
        for m in re.findall(pat, js):
            if 3 < len(m) < 200 and " " not in m:
                endpoints.add(m)
    return sorted(endpoints)

def extract_js_secrets(js):
    findings = {}
    for name, pattern in SECRET_PATTERNS.items():
        try:
            matches = re.findall(pattern, js)
            if matches:
                findings[name] = list(set(matches[:5]))
        except Exception:
            pass
    return findings

def run_js_recon(base_url):
    results = {"endpoints":[], "secrets":{}, "js_files":[], "graphql":False, "websockets":[]}
    r = safe_get(base_url)
    if not r: return results
    soup = BeautifulSoup(r.text, "html.parser")
    parsed = urllib.parse.urlparse(base_url)
    js_urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):   js_urls.append(src)
        elif src.startswith("//"):   js_urls.append("https:" + src)
        elif src.startswith("/"):    js_urls.append(f"{parsed.scheme}://{parsed.netloc}{src}")
    results["js_files"] = js_urls[:30]
    all_js = "\n".join(s.get_text() for s in soup.find_all("script", src=False))
    for js_url in js_urls[:15]:
        jr = safe_get(js_url, timeout=12)
        if jr: all_js += jr.text
    results["endpoints"] = extract_js_endpoints(all_js)
    results["secrets"]   = extract_js_secrets(all_js)
    results["graphql"]   = any("graphql" in ep.lower() for ep in results["endpoints"])
    ws_pat = re.findall(r'wss?://[a-zA-Z0-9._/\-:]+', all_js)
    results["websockets"] = list(set(ws_pat))
    return results

def print_js(data):
    section("JavaScript Reconnaissance")
    info(f"Found {len(data['js_files'])} JS files")
    for u in data["js_files"][:6]: console.print(f"    [dim]{u}[/dim]")
    if data["websockets"]:
        console.print(f"\n  [yellow]🔌 WebSocket endpoints:[/yellow]")
        for w in data["websockets"]: console.print(f"    [cyan]{w}[/cyan]")
    if data["graphql"]:
        warn("GraphQL endpoint detected!")
    if data["endpoints"]:
        console.print(f"\n  [yellow]🔗 {len(data['endpoints'])} API Endpoints extracted:[/yellow]")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        t.add_column("EP", style="white")
        for ep in data["endpoints"][:40]: t.add_row(ep)
        console.print(t)
    if data["secrets"]:
        console.print()
        warn("[bold red]🚨 POTENTIAL SECRETS / SENSITIVE DATA IN JS[/bold red]")
        for stype, matches in data["secrets"].items():
            console.print(f"    [bold red]{stype}[/bold red] ({len(matches)} match{'es' if len(matches)>1 else ''})")
            for m in matches[:2]:
                display = (m[:30] + "…") if len(m) > 30 else m
                console.print(f"      [red]{display}[/red]")
    else:
        ok("No obvious secrets detected in JS")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 8 — GEO & ASN
# ═══════════════════════════════════════════════════════════════════════════════
def run_geo(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if r.ok:
            d = r.json()
            return {
                "ip":d.get("ip",ip),"city":d.get("city",""),
                "region":d.get("region",""),"country":d.get("country_name",""),
                "country_code":d.get("country",""),"org":d.get("org",""),
                "asn":d.get("asn",""),"timezone":d.get("timezone",""),
                "latitude":d.get("latitude",""),"longitude":d.get("longitude",""),
                "currency":d.get("currency",""),"calling_code":d.get("country_calling_code",""),
            }
    except Exception: pass
    return {}

def print_geo(data):
    if not data: return
    section("Geo & Infrastructure")
    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
    t.add_column("Key",style="bold cyan",width=16); t.add_column("Value",style="white")
    for k,v in data.items():
        if v and k not in ["latitude","longitude"]: t.add_row(k.replace("_"," ").title(), str(v))
    if data.get("latitude") and data.get("longitude"):
        t.add_row("Coordinates", f"{data['latitude']}, {data['longitude']}")
    console.print(t)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 9 — PORT SCAN
# ═══════════════════════════════════════════════════════════════════════════════
def scan_ports(ip, ports=None):
    if ports is None: ports = list(COMMON_PORTS.keys())
    open_ports = {}
    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0: return port, COMMON_PORTS.get(port,"Unknown")
            s.close()
        except Exception: pass
        return None, None
    with ThreadPoolExecutor(max_workers=60) as ex:
        for port, svc in ex.map(lambda p: check(p), ports):
            if port: open_ports[port] = svc
    return dict(sorted(open_ports.items()))

def print_ports(data):
    if not data: return
    section("Port Scan")
    t = Table(box=box.SIMPLE, padding=(0,2))
    t.add_column("Port",    style="bold yellow", width=8)
    t.add_column("Service", style="bold white",  width=16)
    t.add_column("Risk",    style="bold red")
    for port, svc in data.items():
        risk = HIGH_RISK_PORTS.get(port, "")
        t.add_row(str(port), svc, risk)
    console.print(t)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 10 — PHONE INTELLIGENCE 🆕
# ═══════════════════════════════════════════════════════════════════════════════
def run_phone_intel(phone_number, default_region="IN"):
    section("Phone Number Intelligence")
    results = {"input": phone_number}
    if not PHONE_LIB:
        err("phonenumbers library not installed. Run: pip install phonenumbers")
        return results

    try:
        # Parse
        parsed = phonenumbers.parse(phone_number, default_region)
        results["parsed"]         = True
        results["valid"]          = phonenumbers.is_valid_number(parsed)
        results["possible"]       = phonenumbers.is_possible_number(parsed)
        results["e164"]           = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        results["international"]  = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        results["national"]       = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        results["country_code"]   = parsed.country_code
        results["region"]         = phonenumbers.region_code_for_number(parsed)

        # Carrier & Geo
        results["carrier"]        = carrier.name_for_number(parsed, "en") or "Unknown"
        results["geo_desc"]       = geocoder.description_for_number(parsed, "en") or "Unknown"
        results["timezones"]      = list(pn_timezone.time_zones_for_number(parsed))

        # Number type
        num_type = phonenumbers.number_type(parsed)
        type_map = {
            0:"FIXED_LINE", 1:"MOBILE", 2:"FIXED_OR_MOBILE",
            3:"TOLL_FREE", 4:"PREMIUM_RATE", 6:"VOIP",
            7:"PERSONAL_NUMBER", 9:"UAN", 10:"VOICEMAIL",
        }
        results["line_type"] = type_map.get(num_type, "UNKNOWN")

        # Print
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
        t.add_column("Field", style="bold cyan", width=22)
        t.add_column("Value", style="white")
        t.add_row("Input Number",    phone_number)
        t.add_row("E.164 Format",    results["e164"])
        t.add_row("International",   results["international"])
        t.add_row("National",        results["national"])
        v_badge = "[bold green]✓ VALID[/bold green]" if results["valid"] else "[bold red]✗ INVALID[/bold red]"
        t.add_row("Validity",        v_badge)
        t.add_row("Country",         f"{results['region']} (+{results['country_code']})")
        t.add_row("Carrier/Network", results["carrier"])
        t.add_row("Location",        results["geo_desc"])
        t.add_row("Line Type",       results["line_type"])
        t.add_row("Timezones",       ", ".join(results["timezones"]))
        console.print(t)

        if results["line_type"] == "VOIP":
            warn("VOIP number detected — common in fraud schemes!")

        # Numverify free check (no API key needed for basic)
        console.print("\n[bold yellow]🌐 Checking online presence...[/bold yellow]")
        e164_clean = results["e164"].replace("+","").replace(" ","")
        checks = []

        # WhatsApp check via wa.me
        wa_r = safe_get(f"https://api.whatsapp.com/send?phone={e164_clean}", timeout=8)
        if wa_r and wa_r.status_code == 200 and "invalid" not in wa_r.text.lower():
            checks.append(("WhatsApp", "[yellow]Possible (unverified)[/yellow]"))
        else:
            checks.append(("WhatsApp", "[dim]Unknown[/dim]"))

        # Truecaller lookup via public endpoint (no auth)
        try:
            tc_r = requests.get(
                f"https://search5-noneu.truecaller.com/v2/search",
                params={"q": results["e164"], "countryCode": results["region"],
                        "type": 4, "locAddr": "", "encoding": "json"},
                headers={**HEADERS_UA, "Authorization":"Bearer dummy"},
                timeout=8
            )
            if tc_r and tc_r.status_code in [200, 401]:
                checks.append(("Truecaller DB", "[green]Reachable[/green]"))
        except Exception:
            pass

        # Spam/fraud check via NumLookupAPI (free tier)
        try:
            nl_r = requests.get(
                f"https://api.numlookupapi.com/v1/info/{results['e164']}",
                timeout=8
            )
            if nl_r and nl_r.ok:
                nl = nl_r.json()
                results["numlookup"] = nl
                checks.append(("NumLookup", f"[cyan]Valid={nl.get('valid','?')} Line={nl.get('line_type','?')}[/cyan]"))
        except Exception:
            pass

        if checks:
            for platform, status in checks:
                console.print(f"  [bold]{platform}:[/bold] {status}")

        # Google dorks for the number
        console.print(f"\n[bold yellow]🔍 Suggested Google Dorks:[/bold yellow]")
        dorks = [
            f'"{results["national"]}"',
            f'"{results["e164"]}"',
            f'"{e164_clean}" site:truecaller.com',
            f'"{results["national"]}" (complaint OR fraud OR scam)',
            f'"{results["national"]}" site:facebook.com OR site:instagram.com',
        ]
        for d in dorks:
            console.print(f"  [cyan]https://google.com/search?q={urllib.parse.quote(d)}[/cyan]")

    except phonenumbers.phonenumberutil.NumberParseException as e:
        err(f"Could not parse phone number: {e}")
        results["error"] = str(e)

    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 11 — EMAIL INTELLIGENCE 🆕
# ═══════════════════════════════════════════════════════════════════════════════
def run_email_intel(email):
    section("Email Intelligence")
    results = {"input": email, "checks": {}}

    # 1. Format validation
    email_regex = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    valid_fmt = bool(email_regex.match(email))
    results["valid_format"] = valid_fmt

    if not valid_fmt:
        err(f"Invalid email format: {email}"); return results

    parts = email.split("@")
    username = parts[0]; domain = parts[1]
    results["username"] = username; results["domain"] = domain

    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,1))
    t.add_column("Check",  style="bold cyan", width=24)
    t.add_column("Result", style="white")

    t.add_row("Email",           email)
    t.add_row("Username Part",   username)
    t.add_row("Domain Part",     domain)
    t.add_row("Format Valid",    "[bold green]✓ YES[/bold green]")

    # 2. Disposable check
    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    results["disposable"] = is_disposable
    t.add_row("Disposable?",
              "[bold red]🚨 YES — TEMP MAIL[/bold red]" if is_disposable
              else "[green]No[/green]")

    # 3. MX record check
    mx_ok = False
    try:
        mx_recs = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_list = [str(r.exchange) for r in mx_recs]
        results["mx_records"] = mx_list
        mx_ok = len(mx_list) > 0
        t.add_row("MX Records",  "[green]✓ " + ", ".join(mx_list[:2]) + "[/green]")
    except Exception:
        results["mx_records"] = []
        t.add_row("MX Records",  "[red]✗ No MX — Cannot receive email[/red]")

    # 4. Gravatar check
    md5_hash = hashlib.md5(email.lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
    grav_r = safe_get(gravatar_url, timeout=6)
    has_gravatar = grav_r and grav_r.status_code == 200
    results["gravatar"] = has_gravatar
    results["gravatar_url"] = f"https://www.gravatar.com/avatar/{md5_hash}"
    t.add_row("Gravatar",
              f"[green]✓ Profile photo found! → {gravatar_url}[/green]" if has_gravatar
              else "[dim]No gravatar[/dim]")

    # 5. Free provider check
    free_providers = {
        "gmail.com","yahoo.com","hotmail.com","outlook.com",
        "protonmail.com","icloud.com","aol.com","ymail.com",
        "live.com","msn.com","rediffmail.com",
    }
    is_free = domain.lower() in free_providers
    results["free_provider"] = is_free
    t.add_row("Provider Type",
              "[yellow]Free/Public" + (" (Gmail)" if "gmail" in domain else "") + "[/yellow]"
              if is_free else "[green]Corporate/Custom domain[/green]")

    # 6. GitHub commit search
    try:
        gh_r = requests.get(
            f"https://api.github.com/search/commits?q=author-email:{email}&per_page=5",
            headers={**HEADERS_UA, "Accept":"application/vnd.github.cloak-preview"},
            timeout=10
        )
        if gh_r and gh_r.ok:
            gh = gh_r.json()
            gh_count = gh.get("total_count", 0)
            results["github_commits"] = gh_count
            if gh_count > 0:
                t.add_row("GitHub Commits", f"[green]✓ {gh_count} commit(s) found[/green]")
                items = gh.get("items", [])
                if items:
                    results["github_repos"] = [
                        {"repo": i["repository"]["full_name"], "msg": i["commit"]["message"][:50]}
                        for i in items[:3]
                    ]
            else:
                t.add_row("GitHub Commits", "[dim]No public commits[/dim]")
    except Exception:
        pass

    # 7. HaveIBeenPwned check (public API — no key for v3)
    try:
        hibp_r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={**HEADERS_UA, "hibp-api-key": ""},
            timeout=10
        )
        if hibp_r and hibp_r.status_code == 200:
            breaches = hibp_r.json()
            results["breaches"] = [b.get("Name","") for b in breaches]
            t.add_row("Data Breaches",
                      f"[bold red]🚨 IN {len(breaches)} BREACH(ES)! " +
                      ", ".join(b.get("Name","") for b in breaches[:3]) + "[/bold red]")
        elif hibp_r and hibp_r.status_code == 404:
            t.add_row("Data Breaches", "[green]✓ Not found in known breaches[/green]")
        elif hibp_r and hibp_r.status_code == 401:
            t.add_row("Data Breaches", "[dim]API key required for HIBP[/dim]")
    except Exception:
        t.add_row("Data Breaches", "[dim]Could not check[/dim]")

    # 8. Hunter.io domain check (no key)
    try:
        hunter_r = requests.get(
            f"https://api.hunter.io/v2/email-verifier?email={email}",
            timeout=8
        )
        if hunter_r and hunter_r.ok:
            h = hunter_r.json().get("data",{})
            t.add_row("Hunter.io Status", str(h.get("status","unknown")))
    except Exception:
        pass

    console.print(t)

    # 9. Social profile hints
    console.print(f"\n[bold yellow]🔍 Suggested Investigation Queries:[/bold yellow]")
    queries = [
        f'"{email}"',
        f'"{email}" (fraud OR scam OR complaint)',
        f'"{username}" site:github.com',
        f'"{username}" site:linkedin.com',
        f'"{email}" site:pastebin.com',
        f'"{email}" filetype:pdf OR filetype:xls',
    ]
    for q in queries:
        console.print(f"  [cyan]https://google.com/search?q={urllib.parse.quote(q)}[/cyan]")

    # GitHub repos
    if results.get("github_repos"):
        console.print(f"\n[bold yellow]GitHub Activity:[/bold yellow]")
        for repo in results["github_repos"]:
            console.print(f"  [green]{repo['repo']}[/green] — {repo['msg']}")

    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 12 — USERNAME HUNT 🆕
# ═══════════════════════════════════════════════════════════════════════════════
def run_username_hunt(username):
    section(f"Username Hunt: @{username}")
    found, not_found, errors = [], [], []
    results = {"username": username, "found": [], "not_found": []}

    def check_site(site):
        url = site["url"].format(username)
        try:
            r = requests.get(url, timeout=8, headers=HEADERS_UA, allow_redirects=True)
            if r and r.status_code == 200:
                if site["err"].lower() not in r.text.lower():
                    return site["name"], url, "FOUND"
            return site["name"], url, "NOT_FOUND"
        except Exception:
            return site["name"], url, "ERROR"

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(bar_width=25), TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task(f"[cyan]Hunting @{username}...", total=len(USERNAME_SITES))
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(check_site, s): s for s in USERNAME_SITES}
            for f in as_completed(futures):
                name, url, status = f.result()
                prog.advance(task)
                if   status == "FOUND":     found.append((name, url))
                elif status == "NOT_FOUND": not_found.append(name)
                else:                       errors.append(name)

    results["found"]     = [{"site":n,"url":u} for n,u in found]
    results["not_found"] = not_found

    if found:
        console.print(f"\n[bold green]✓ Found on {len(found)} platform(s):[/bold green]")
        t = Table(box=box.SIMPLE, padding=(0,1))
        t.add_column("Platform", style="bold green", width=18)
        t.add_column("URL",      style="cyan")
        for name, url in sorted(found):
            t.add_row(name, url)
        console.print(t)
    else:
        warn("Username not found on checked platforms")

    console.print(f"\n[dim]Not found on {len(not_found)} platforms | Errors: {len(errors)}[/dim]")
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 13 — ROBOTS & SITEMAP
# ═══════════════════════════════════════════════════════════════════════════════
def run_robots(base_url):
    results = {"disallowed":[], "allowed":[], "sitemaps":[], "raw":""}
    r = safe_get(f"{base_url}/robots.txt")
    if r and r.ok and "text" in r.headers.get("Content-Type",""):
        results["raw"] = r.text[:3000]
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":",1)[1].strip()
                if p: results["disallowed"].append(p)
            elif line.lower().startswith("allow:"):
                p = line.split(":",1)[1].strip()
                if p: results["allowed"].append(p)
            elif line.lower().startswith("sitemap:"):
                results["sitemaps"].append(line.split(":",1)[1].strip())
    return results

def print_robots(data):
    if not data["raw"]: return
    section("robots.txt Analysis")
    if data["disallowed"]:
        console.print(f"[yellow]🚫 {len(data['disallowed'])} Disallowed paths:[/yellow]")
        for p in data["disallowed"][:20]:
            risk = "[bold red]← INTERESTING[/bold red]" if any(x in p.lower() for x in
                   ["admin","backup","api","config","private","secret","internal"]) else ""
            console.print(f"  [red]{p}[/red]  {risk}")
    if data["sitemaps"]:
        console.print(f"\n[yellow]🗺  Sitemaps:[/yellow]")
        for s in data["sitemaps"]: console.print(f"  [cyan]{s}[/cyan]")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 14 — EXPORT
# ═══════════════════════════════════════════════════════════════════════════════
def export_results(target, all_data, fmt="all"):
    slug = safe_slug(target)      # ← FIXED: no more path-separator bugs
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out  = Path(f"osint_{slug}_{ts}")
    out.mkdir(parents=True, exist_ok=True)

    if fmt in ("json","all"):
        p = out / "report.json"
        with open(p,"w") as f: json.dump(all_data, f, indent=2, default=str)
        ok(f"JSON  → {p}")

    if fmt in ("md","markdown","all"):
        p = out / "report.md"
        md = build_md(target, all_data)
        with open(p,"w") as f: f.write(md)
        ok(f"Markdown → {p}")

    if fmt in ("csv","all"):
        # Flat findings CSV
        p = out / "findings.csv"
        rows = []
        for path_item in all_data.get("paths",[]):
            rows.append({"type":"path","value":path_item["url"],"status":path_item["status"]})
        for sub in all_data.get("subdomains_passive",[]):
            rows.append({"type":"subdomain","value":sub,"status":"passive"})
        for ep in all_data.get("js",{}).get("endpoints",[]):
            rows.append({"type":"endpoint","value":ep,"status":"js"})
        if rows:
            with open(p,"w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["type","value","status"])
                w.writeheader(); w.writerows(rows)
            ok(f"CSV   → {p}")

    return str(out)

def build_md(target, data):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"# OSINT Report: `{target}`", f"*Generated: {ts}*", "---", ""]
    w = data.get("whois",{})
    if w and "error" not in w:
        lines += ["## WHOIS",
                  f"- **Registrar**: {w.get('registrar','—')}",
                  f"- **Org**: {w.get('org','—')}",
                  f"- **Country**: {w.get('country','—')}",
                  f"- **Created**: {w.get('creation_date','—')}",
                  f"- **Expires**: {w.get('expiration_date','—')}",
                  f"- **Domain Age**: {w.get('domain_age_days','?')} days",
                  ""]
    if data.get("tech"):
        lines += ["## Tech Stack", "- " + ", ".join(data["tech"]), ""]
    if data.get("cloud"):
        lines += ["## Cloud/CDN", "- " + ", ".join(data["cloud"]), ""]
    subs = data.get("subdomains_passive",[])
    if subs:
        lines += [f"## Subdomains ({len(subs)})"] + [f"- {s}" for s in subs[:50]] + [""]
    paths = data.get("paths",[])
    if paths:
        lines += ["## Interesting Paths"] + [f"- [{p['status']}] {p['url']}" for p in paths] + [""]
    secs = data.get("js",{}).get("secrets",{})
    if secs:
        lines += ["## ⚠ Potential Secrets"] + [f"- **{k}**: {len(v)} match(es)" for k,v in secs.items()] + [""]
    sec_hdrs = data.get("security_headers",{})
    missing = [k for k,v in sec_hdrs.items() if not v["present"] and v["severity"] in ["red","yellow"]]
    if missing:
        lines += ["## Missing Security Headers"] + [f"- {m}" for m in missing] + [""]
    geo = data.get("geo",{})
    if geo:
        lines += ["## Infrastructure",
                  f"- **IP**: {geo.get('ip','—')}",
                  f"- **Location**: {geo.get('city','')}, {geo.get('country','—')}",
                  f"- **ASN**: {geo.get('asn','—')} ({geo.get('org','—')})",
                  ""]
    ports = data.get("ports",{})
    if ports:
        lines += [f"## Open Ports ({len(ports)})"] + [f"- **{p}**: {s}" for p,s in ports.items()] + [""]
    return "\n".join(lines)

# ═══════════════════════════════════════════════════════════════════════════════
# FULL DOMAIN SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════
def run_domain_scan(target, args):
    domain = re.sub(r'^https?://', '', target).strip("/").split("/")[0]
    ext    = tldextract.extract(domain)
    root   = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    console.print(BANNER)
    console.print(Panel(
        f"[bold white]Target:[/bold white]      [bold cyan]{domain}[/bold cyan]\n"
        f"[bold white]Root Domain:[/bold white] [cyan]{root}[/cyan]\n"
        f"[bold white]Scan Mode:[/bold white]   {'[bold red]DEEP[/bold red]' if getattr(args,'deep',False) else '[yellow]STANDARD[/yellow]'}\n"
        f"[bold white]Started:[/bold white]     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold yellow]🎯 OSINT SCAN INITIATED[/bold yellow]",
        border_style="yellow", padding=(1,2),
    ))

    all_data = {"target":{"domain":domain,"root":root,"scan_time":datetime.now().isoformat()}}

    # ── Core recon ─────────────────────────────────────────────────────────────
    steps = []
    if not getattr(args,"skip_whois",False):   steps.append(("WHOIS",        lambda: run_whois(root)))
    if not getattr(args,"skip_dns",False):     steps.append(("DNS",          lambda: run_dns(domain)))
    if not getattr(args,"skip_headers",False): steps.append(("HTTP Headers", lambda: run_headers(domain)))
    if not getattr(args,"skip_ssl",False):     steps.append(("SSL/TLS",      lambda: run_ssl(domain)))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(bar_width=30), TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("[cyan]Core recon...", total=len(steps))
        for name, fn in steps:
            prog.update(task, description=f"[cyan]Scanning: {name}...")
            try:    all_data[name.lower().replace(" ","_")] = fn()
            except Exception as e: all_data[name.lower().replace(" ","_")] = {"error": str(e)}
            prog.advance(task)

    # Print core results
    if "whois"       in all_data: print_whois(all_data["whois"])
    if "dns"         in all_data: print_dns(all_data["dns"], domain)

    # IP + Geo
    ip = resolve_ip(domain)
    if ip:
        all_data["ip"] = ip
        console.print(f"\n[bold yellow]🌐 IP:[/bold yellow] [bold cyan]{ip}[/bold cyan]")
        if not getattr(args,"skip_geo",False):
            with console.status("[cyan]Geo lookup..."):
                geo = run_geo(ip)
            all_data["geo"] = geo
            print_geo(geo)

    # HTTP analysis + Tech
    hdr = all_data.get("http_headers",{})
    if hdr and "headers" in hdr:
        raw_h = hdr["headers"]
        r_page = safe_get(f"https://{domain}")
        html = r_page.text if r_page else ""
        all_data["html_sample"] = html[:10000]
        tech  = detect_tech(domain, raw_h, html)
        cloud = detect_cloud(domain, raw_h, all_data.get("dns",{}))
        all_data["tech"]  = tech
        all_data["cloud"] = cloud
        if tech:
            section("Technology Stack")
            cols = [Panel(f"[bold white]{t}[/bold white]", border_style="cyan", padding=(0,2)) for t in tech]
            console.print(Columns(cols[:12]))
        if cloud:
            info(f"Cloud/CDN: [bold cyan]{', '.join(cloud)}[/bold cyan]")
        sec = run_security_headers(raw_h)
        all_data["security_headers"] = sec
        print_headers_ssl(hdr, all_data.get("ssl_tls",{}), sec)

    # robots.txt
    if not getattr(args,"skip_robots",False):
        robots = run_robots(f"https://{domain}")
        all_data["robots"] = robots
        print_robots(robots)

    # Subdomains
    if not getattr(args,"skip_subs",False):
        with console.status("[cyan]crt.sh passive enum..."):
            passive = crtsh_subdomains(root)
        with console.status("[cyan]HackerTarget enum..."):
            passive2 = hackertarget_subdomains(root)
        passive = sorted(set(passive) | set(passive2))
        info(f"Passive: {len(passive)} subdomains")
        brute = []
        if not getattr(args,"no_brute",False):
            wl = COMMON_SUBDOMAINS
            if getattr(args,"deep",False): wl = wl * 1  # same list; extend if you have a file
            with console.status(f"[cyan]Brute-forcing {len(wl)} subdomains..."):
                brute = bruteforce_subdomains(root, wl)
            info(f"Brute: {len(brute)} new subdomains")
        all_data["subdomains_passive"] = passive
        all_data["subdomains_brute"]   = [{"fqdn":f,"ip":i} for f,i in brute]
        print_subdomains(passive, brute)

    # Path discovery
    if not getattr(args,"skip_paths",False):
        paths_to_check = INTERESTING_PATHS
        with console.status(f"[cyan]Checking {len(paths_to_check)} paths..."):
            found_paths = run_path_discovery(f"https://{domain}", paths_to_check)
        all_data["paths"] = found_paths
        print_paths(found_paths)

    # JS recon
    if not getattr(args,"skip_js",False):
        with console.status("[cyan]JS reconnaissance..."):
            js_data = run_js_recon(f"https://{domain}")
        all_data["js"] = js_data
        print_js(js_data)

    # Port scan
    if not getattr(args,"skip_ports",False) and ip:
        ports = list(COMMON_PORTS.keys())
        with console.status(f"[cyan]Port scanning {ip} ({len(ports)} ports)..."):
            open_ports = scan_ports(ip, ports)
        all_data["ports"] = open_ports
        print_ports(open_ports)

    # Email harvest from HTML
    html = all_data.get("html_sample","")
    harvested = set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html))
    if harvested:
        all_data["harvested_emails"] = list(harvested)
        section("Harvested Emails")
        for e in harvested: console.print(f"  [cyan]{e}[/cyan]")

    # ── Summary ────────────────────────────────────────────────────────────────
    section("SCAN COMPLETE")
    summary = [
        ("WHOIS",         "registrar" in all_data.get("whois",{})),
        ("DNS Records",   bool(all_data.get("dns"))),
        ("SSL/TLS",       "days_left" in all_data.get("ssl_tls",{})),
        ("Tech Stack",    len(all_data.get("tech",[]))),
        ("Cloud/CDN",     len(all_data.get("cloud",[]))),
        ("Subdomains",    len(all_data.get("subdomains_passive",[]))),
        ("Paths Found",   len(all_data.get("paths",[]))),
        ("JS Endpoints",  len(all_data.get("js",{}).get("endpoints",[]))),
        ("JS Secrets",    len(all_data.get("js",{}).get("secrets",{}))),
        ("Open Ports",    len(all_data.get("ports",{}))),
        ("Emails",        len(all_data.get("harvested_emails",[]))),
    ]
    t = Table(box=box.DOUBLE_EDGE, padding=(0,2),
              title="[bold yellow]📊 Scan Summary[/bold yellow]")
    t.add_column("Module", style="bold white", width=20)
    t.add_column("Result", justify="right")
    for name, val in summary:
        if isinstance(val, bool):
            t.add_row(name, "[bold green]✓[/bold green]" if val else "[dim]—[/dim]")
        else:
            color = "bold green" if val > 0 else "dim"
            t.add_row(name, f"[{color}]{val}[/{color}]")
    console.print(t)
    return all_data

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="OSINT v2.0 — Cyber Fraud Catcher Edition",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python osint_tool.py example.com                  # Full domain scan
  python osint_tool.py jeeadv.ac.in                 # Works with any domain
  python osint_tool.py example.com --deep           # Deep mode (more paths)
  python osint_tool.py --phone +919876543210        # Phone intelligence
  python osint_tool.py --phone +14155552671         # International phone
  python osint_tool.py --email someone@gmail.com    # Email intelligence
  python osint_tool.py --username johndoe           # Username hunt (40+ sites)
  python osint_tool.py example.com --export json    # JSON only export
  python osint_tool.py example.com --skip-ports     # Skip port scan
  python osint_tool.py example.com --no-brute       # No subdomain brute-force
        """
    )
    parser.add_argument("target",         nargs="?", help="Target domain")
    parser.add_argument("--phone",        help="Phone number to investigate (e.g. +919876543210)")
    parser.add_argument("--email",        help="Email address to investigate")
    parser.add_argument("--username",     help="Username to hunt across platforms")
    parser.add_argument("--deep",         action="store_true", help="Deep scan (more paths/subdomains)")
    parser.add_argument("--export",       choices=["json","md","csv","all"], default="all")
    parser.add_argument("--no-export",    action="store_true")
    parser.add_argument("--skip-whois",   action="store_true")
    parser.add_argument("--skip-dns",     action="store_true")
    parser.add_argument("--skip-headers", action="store_true")
    parser.add_argument("--skip-ssl",     action="store_true")
    parser.add_argument("--skip-subs",    action="store_true")
    parser.add_argument("--skip-paths",   action="store_true")
    parser.add_argument("--skip-js",      action="store_true")
    parser.add_argument("--skip-ports",   action="store_true")
    parser.add_argument("--skip-geo",     action="store_true")
    parser.add_argument("--skip-robots",  action="store_true")
    parser.add_argument("--no-brute",     action="store_true")
    args = parser.parse_args()

    console.print(BANNER)

    all_data = {}
    target_label = ""

    # ── Phone mode ─────────────────────────────────────────────────────────────
    if args.phone:
        target_label = args.phone
        all_data["phone"] = run_phone_intel(args.phone)

    # ── Email mode ─────────────────────────────────────────────────────────────
    if args.email:
        target_label = args.email
        all_data["email"] = run_email_intel(args.email)

    # ── Username mode ──────────────────────────────────────────────────────────
    if args.username:
        target_label = args.username
        all_data["username"] = run_username_hunt(args.username)

    # ── Domain mode ────────────────────────────────────────────────────────────
    if args.target:
        target_label = args.target
        domain_data = run_domain_scan(args.target, args)
        all_data.update(domain_data)

    if not any([args.phone, args.email, args.username, args.target]):
        parser.print_help()
        return

    # ── Export ─────────────────────────────────────────────────────────────────
    if not args.no_export and target_label:
        section("Exporting Results")
        out_dir = export_results(target_label, all_data, args.export)
        console.print(f"\n[bold green]📁 Saved to:[/bold green] [cyan]{out_dir}/[/cyan]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(0)
