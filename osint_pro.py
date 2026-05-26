#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║          OSINT PRO v3.0 — Police Intelligence Edition                          ║
║  Phone · Email · Username · Domain · Cross-Pivot · AI Narrative · HTML Report  ║
║  SpiderFoot-class · Sherlock-class · Async · 300+ Sources · India-Optimised    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  Usage:                                                                         ║
║    python osint_pro.py example.com                   # Full domain recon        ║
║    python osint_pro.py --phone +919876543210          # Deep phone intel         ║
║    python osint_pro.py --email target@gmail.com       # Email investigation      ║
║    python osint_pro.py --username johndoe             # Username hunt 200+ sites ║
║    python osint_pro.py --phone +91XXX --pivot         # Auto cross-pivot         ║
║    python osint_pro.py --phone +91XXX --ai-report     # AI narrative + HTML      ║
║    python osint_pro.py example.com --deep --ai-report # Full deep scan + AI      ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

import sys, os, re, json, time, hashlib, argparse, urllib.parse, socket, ssl
import asyncio, csv, smtplib, struct, ipaddress
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any, Set
from email.utils import parseaddr

import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois as whois_lib
import tldextract

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.tree import Tree
from rich.columns import Columns
from rich import box
from rich.text import Text
from rich.align import Align

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
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

import urllib3
urllib3.disable_warnings()

console = Console(highlight=True)

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════
BANNER = """[bold cyan]
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ██████╗ ██████╗  ██████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔══██╗██╔═══██╗
██║   ██║███████╗██║██╔██╗ ██║   ██║       ██████╔╝██████╔╝██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔═══╝ ██╔══██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║       ██║     ██║  ██║╚██████╔╝
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝[/bold cyan]
[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]
[bold white]   v3.0 Police Intelligence Edition  |  SpiderFoot·Sherlock·MrHolmes Class
   Phone · Email · Username · Domain · Cross-Pivot · AI Narrative · 300+ Sources[/bold white]
[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]
"""

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]
_ua_i = 0

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","throwam.com",
    "yopmail.com","sharklasers.com","grr.la","spam4.me","trashmail.com","dispostable.com",
    "mailnull.com","spamgourmet.com","fakeinbox.com","maildrop.cc","temp-mail.org",
    "discard.email","emailondeck.com","mintemail.com","throwaway.email","moakt.com",
    "anonbox.net","spambox.us","getairmail.com","mailnesia.com","spamgourmet.com",
    "trashmail.at","mytemp.email","getnada.com","harakirimail.com","spamthisplease.com",
    "mailpoof.com","tempr.email","spamfree24.org","spam.la","wegwerfmail.de",
    "guerrillamailblock.com","armyspy.com","cuvox.de","dayrep.com","einrot.com",
    "fleckens.hu","gustr.com","incognitomail.com","jourrapide.com","laoeq.com",
    "rhyta.com","semphone.com","superrito.com","teleworm.us","tempinbox.com",
}

VOIP_PROVIDERS = {
    "google voice","twilio","vonage","magicjack","skype","textnow","textfree",
    "burner","hushed","mysudo","2ndline","sideline","google","bandwidth","telnyx",
    "plivo","signalwire","ringcentral","8x8","dialpad","grasshopper","ooma","nextiva",
}

INDIA_PREFIXES = {
    "6000":("Reliance Jio","Various","4G/5G"),   "6001":("Reliance Jio","Various","4G/5G"),
    "6002":("Reliance Jio","Various","4G/5G"),   "6003":("Reliance Jio","Various","4G/5G"),
    "7000":("Reliance Jio","Various","4G/5G"),   "7001":("Reliance Jio","Various","4G/5G"),
    "7002":("Reliance Jio","Various","4G/5G"),   "7003":("Reliance Jio","Various","4G/5G"),
    "8000":("Reliance Jio","Various","4G/5G"),   "8001":("Reliance Jio","Various","4G/5G"),
    "9810":("Airtel","Delhi","GSM"),             "9811":("Airtel","Delhi","GSM"),
    "9818":("Airtel","Delhi","GSM"),             "9871":("Airtel","Delhi","GSM"),
    "9821":("Airtel","Mumbai","GSM"),            "9869":("Airtel","Mumbai","GSM"),
    "9823":("Airtel","Maharashtra","GSM"),       "9876":("Airtel","Punjab","GSM"),
    "9855":("Airtel","Punjab","GSM"),            "9900":("Airtel","Karnataka","GSM"),
    "9980":("Airtel","Karnataka","GSM"),         "9440":("Airtel","Andhra Pradesh","GSM"),
    "9849":("Airtel","Andhra Pradesh","GSM"),    "9600":("Airtel","Tamil Nadu","GSM"),
    "9842":("Airtel","Tamil Nadu","GSM"),        "9870":("Airtel","Delhi","GSM"),
    "9820":("Vodafone Idea (Vi)","Mumbai","GSM"),"9833":("Vodafone Idea (Vi)","Mumbai","GSM"),
    "9822":("Vodafone Idea (Vi)","Maharashtra","GSM"), "9902":("Vodafone Idea (Vi)","Karnataka","GSM"),
    "9888":("BSNL","Punjab","GSM"),              "9901":("BSNL","Karnataka","GSM"),
    "9986":("BSNL","Karnataka","GSM"),           "9868":("BSNL","Delhi","GSM"),
    "9415":("BSNL","UP East","GSM"),             "9450":("BSNL","UP East","GSM"),
    "8448":("Airtel","Delhi","4G"),              "8527":("Reliance Jio","Various","4G"),
    "9958":("Airtel","Delhi","GSM"),             "9599":("Airtel","Delhi","GSM"),
}

FRAUD_PATTERNS_IN = {
    "140": "TRAI Telemarketer Series — Bulk calling, often spoofed",
    "160": "OTP/Transactional SMS — Commonly spoofed in phishing",
    "000": "International routing anomaly",
}

SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":    r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":      r"[a-z0-9-]+\.firebaseio\.com",
    "Firebase Config":   r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Stripe Live Key":   r"sk_live_[a-zA-Z0-9]{24,}",
    "Stripe Public":     r"pk_live_[a-zA-Z0-9]{24,}",
    "GitHub PAT":        r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth":      r"gho_[a-zA-Z0-9]{36}",
    "Slack Token":       r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook":     r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,}",
    "Discord Token":     r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27}",
    "Discord Webhook":   r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "Twilio SID":        r"AC[a-z0-9]{32}",
    "SendGrid Key":      r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "JWT Token":         r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
    "SSH Private Key":   r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic Password":  r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "Generic Secret":    r"(?i)(?:secret|api_?key|auth_?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Phone Number (IN)": r"(?<!\d)(?:\+91|0)?[6-9]\d{9}(?!\d)",
    "Email Address":     r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "IP Address":        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "UPI ID":            r"[a-zA-Z0-9.\-_+]+@[a-zA-Z0-9]+",
    "Aadhaar Pattern":   r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "PAN Pattern":       r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "Crypto BTC Addr":   r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "Crypto ETH Addr":   r"\b0x[a-fA-F0-9]{40}\b",
}

USERNAME_SITES = [
    # MAJOR SOCIAL MEDIA
    {"name":"GitHub",        "url":"https://github.com/{}",                    "err":"Not Found",                    "status":404},
    {"name":"Twitter/X",     "url":"https://x.com/{}",                         "err":"This account doesn't exist",   "status":404},
    {"name":"Instagram",     "url":"https://www.instagram.com/{}/",            "err":"Sorry, this page",             "status":404},
    {"name":"Reddit",        "url":"https://www.reddit.com/user/{}/",          "err":"Sorry, nobody on Reddit",      "status":404},
    {"name":"TikTok",        "url":"https://www.tiktok.com/@{}",               "err":"Couldn't find this account",   "status":404},
    {"name":"YouTube",       "url":"https://www.youtube.com/@{}",              "err":"not available",                "status":404},
    {"name":"Pinterest",     "url":"https://www.pinterest.com/{}/",            "err":"Sorry! We couldn't find",      "status":404},
    {"name":"Facebook",      "url":"https://www.facebook.com/{}",              "err":"Page Not Found",               "status":404},
    {"name":"Snapchat",      "url":"https://www.snapchat.com/add/{}",          "err":"not found",                    "status":404},
    {"name":"Threads",       "url":"https://www.threads.net/@{}",              "err":"not found",                    "status":404},
    {"name":"Bluesky",       "url":"https://bsky.app/profile/{}",              "err":"404",                          "status":404},
    {"name":"Mastodon",      "url":"https://mastodon.social/@{}",              "err":"404",                          "status":404},
    {"name":"BeReal",        "url":"https://bere.al/{}",                       "err":"404",                          "status":404},
    # MESSAGING & COMMUNITIES
    {"name":"Telegram",      "url":"https://t.me/{}",                          "err":"If you have Telegram",         "status":200},
    {"name":"Discord",       "url":"https://discord.com/users/{}",             "err":"404",                          "status":404},
    {"name":"Kik",           "url":"https://kik.me/{}",                        "err":"404",                          "status":404},
    {"name":"VKontakte",     "url":"https://vk.com/{}",                        "err":"not found",                    "status":200},
    # DEVELOPER & CODE
    {"name":"GitLab",        "url":"https://gitlab.com/{}",                    "err":"404",                          "status":404},
    {"name":"Bitbucket",     "url":"https://bitbucket.org/{}",                 "err":"404",                          "status":404},
    {"name":"HackerNews",    "url":"https://news.ycombinator.com/user?id={}",  "err":"No such user",                 "status":200},
    {"name":"Dev.to",        "url":"https://dev.to/{}",                        "err":"404",                          "status":404},
    {"name":"Hashnode",      "url":"https://hashnode.com/@{}",                 "err":"404",                          "status":404},
    {"name":"CodePen",       "url":"https://codepen.io/{}",                    "err":"404",                          "status":404},
    {"name":"Replit",        "url":"https://replit.com/@{}",                   "err":"404",                          "status":404},
    {"name":"NPM",           "url":"https://www.npmjs.com/~{}",                "err":"404",                          "status":404},
    {"name":"PyPI",          "url":"https://pypi.org/user/{}/",                "err":"404",                          "status":404},
    {"name":"DockerHub",     "url":"https://hub.docker.com/u/{}/",             "err":"404",                          "status":404},
    {"name":"Pastebin",      "url":"https://pastebin.com/u/{}",                "err":"Not Found",                    "status":404},
    {"name":"Keybase",       "url":"https://keybase.io/{}",                    "err":"404",                          "status":404},
    {"name":"HackerRank",    "url":"https://www.hackerrank.com/{}",            "err":"404",                          "status":404},
    {"name":"LeetCode",      "url":"https://leetcode.com/{}/",                 "err":"404",                          "status":404},
    {"name":"Codeforces",    "url":"https://codeforces.com/profile/{}",        "err":"not found",                    "status":200},
    {"name":"Kaggle",        "url":"https://www.kaggle.com/{}",                "err":"404",                          "status":404},
    {"name":"HuggingFace",   "url":"https://huggingface.co/{}",                "err":"404",                          "status":404},
    {"name":"HackerEarth",   "url":"https://www.hackerearth.com/@{}",          "err":"404",                          "status":404},
    {"name":"GeeksForGeeks", "url":"https://auth.geeksforgeeks.org/user/{}",   "err":"404",                          "status":404},
    {"name":"AtCoder",       "url":"https://atcoder.jp/users/{}",              "err":"404",                          "status":404},
    # GAMING
    {"name":"Steam",         "url":"https://steamcommunity.com/id/{}",         "err":"The specified profile",        "status":200},
    {"name":"Twitch",        "url":"https://www.twitch.tv/{}",                 "err":"Sorry. Unless you",            "status":404},
    {"name":"Roblox",        "url":"https://www.roblox.com/user.aspx?username={}","err":"not found",                 "status":200},
    {"name":"Chess.com",     "url":"https://www.chess.com/member/{}",          "err":"404",                          "status":404},
    {"name":"Lichess",       "url":"https://lichess.org/@/{}",                 "err":"404",                          "status":404},
    {"name":"PSN Profiles",  "url":"https://psnprofiles.com/{}",               "err":"not found",                    "status":404},
    {"name":"Xbox Gamertag", "url":"https://xboxgamertag.com/search/{}",       "err":"No results",                   "status":200},
    # PROFESSIONAL
    {"name":"LinkedIn",      "url":"https://www.linkedin.com/in/{}/",          "err":"Page not found",               "status":404},
    {"name":"AngelList",     "url":"https://angel.co/u/{}",                    "err":"404",                          "status":404},
    {"name":"Product Hunt",  "url":"https://www.producthunt.com/@{}",          "err":"404",                          "status":404},
    {"name":"Fiverr",        "url":"https://www.fiverr.com/{}",                "err":"404",                          "status":404},
    {"name":"Upwork",        "url":"https://www.upwork.com/freelancers/~{}",   "err":"No Profile",                   "status":404},
    {"name":"Gravatar",      "url":"https://en.gravatar.com/{}",               "err":"does not exist",               "status":404},
    {"name":"Xing",          "url":"https://www.xing.com/profile/{}",          "err":"404",                          "status":404},
    # CONTENT CREATORS
    {"name":"Medium",        "url":"https://medium.com/@{}",                   "err":"404",                          "status":404},
    {"name":"Substack",      "url":"https://{}.substack.com",                  "err":"404",                          "status":404},
    {"name":"Blogger",       "url":"https://{}.blogspot.com",                  "err":"404",                          "status":404},
    {"name":"Wordpress",     "url":"https://{}.wordpress.com",                 "err":"doesn't exist",                "status":404},
    {"name":"Tumblr",        "url":"https://{}.tumblr.com",                    "err":"There's nothing here",         "status":404},
    {"name":"Ghost",         "url":"https://{}.ghost.io",                      "err":"404",                          "status":404},
    # CREATIVE & DESIGN
    {"name":"Behance",       "url":"https://www.behance.net/{}",               "err":"404",                          "status":404},
    {"name":"Dribbble",      "url":"https://dribbble.com/{}",                  "err":"404",                          "status":404},
    {"name":"DeviantArt",    "url":"https://www.deviantart.com/{}",            "err":"404",                          "status":404},
    {"name":"ArtStation",    "url":"https://www.artstation.com/{}",            "err":"404",                          "status":404},
    {"name":"Flickr",        "url":"https://www.flickr.com/people/{}",         "err":"not found",                    "status":404},
    {"name":"500px",         "url":"https://500px.com/p/{}",                   "err":"404",                          "status":404},
    {"name":"Unsplash",      "url":"https://unsplash.com/@{}",                 "err":"404",                          "status":404},
    # MUSIC & AUDIO
    {"name":"SoundCloud",    "url":"https://soundcloud.com/{}",                "err":"We can't find that user",      "status":404},
    {"name":"Spotify",       "url":"https://open.spotify.com/user/{}",         "err":"not found",                    "status":404},
    {"name":"Last.fm",       "url":"https://www.last.fm/user/{}",              "err":"Page Not Found",               "status":404},
    {"name":"Bandcamp",      "url":"https://www.bandcamp.com/{}",              "err":"not found",                    "status":404},
    {"name":"Mixcloud",      "url":"https://www.mixcloud.com/{}/",             "err":"404",                          "status":404},
    # VIDEO
    {"name":"Vimeo",         "url":"https://vimeo.com/{}",                     "err":"Sorry, we couldn't find",      "status":404},
    {"name":"Dailymotion",   "url":"https://www.dailymotion.com/{}",           "err":"404",                          "status":404},
    {"name":"Rumble",        "url":"https://rumble.com/user/{}",               "err":"404",                          "status":404},
    {"name":"Odysee",        "url":"https://odysee.com/@{}",                   "err":"404",                          "status":404},
    # Q&A / FORUMS
    {"name":"Quora",         "url":"https://www.quora.com/profile/{}",         "err":"404",                          "status":404},
    {"name":"Disqus",        "url":"https://disqus.com/by/{}",                 "err":"404",                          "status":404},
    # MONETISATION
    {"name":"Patreon",       "url":"https://www.patreon.com/{}",               "err":"404",                          "status":404},
    {"name":"Ko-fi",         "url":"https://ko-fi.com/{}",                     "err":"404",                          "status":404},
    {"name":"Buy Me Coffee", "url":"https://www.buymeacoffee.com/{}",          "err":"404",                          "status":404},
    {"name":"Gumroad",       "url":"https://gumroad.com/{}",                   "err":"not found",                    "status":404},
    # LINK & BIO PAGES
    {"name":"Linktree",      "url":"https://linktr.ee/{}",                     "err":"404",                          "status":404},
    {"name":"About.me",      "url":"https://about.me/{}",                      "err":"404",                          "status":404},
    {"name":"Carrd",         "url":"https://{}.carrd.co",                      "err":"404",                          "status":404},
    {"name":"Flipboard",     "url":"https://flipboard.com/@{}",                "err":"404",                          "status":404},
    # FITNESS & LIFESTYLE
    {"name":"Strava",        "url":"https://www.strava.com/athletes/{}",       "err":"404",                          "status":404},
    {"name":"Goodreads",     "url":"https://www.goodreads.com/{}",             "err":"404",                          "status":404},
    {"name":"Letterboxd",    "url":"https://letterboxd.com/{}",                "err":"404",                          "status":404},
    {"name":"MyAnimeList",   "url":"https://myanimelist.net/profile/{}",       "err":"404",                          "status":404},
    # CRYPTO
    {"name":"Bitcointalk",   "url":"https://bitcointalk.org/index.php?action=profile;username={}","err":"does not exist","status":200},
    # INDIAN PLATFORMS
    {"name":"ShareChat",     "url":"https://sharechat.com/profile/{}",         "err":"404",                          "status":404},
    {"name":"Moj App",       "url":"https://mojapp.in/@{}",                    "err":"404",                          "status":404},
    {"name":"Josh App",      "url":"https://share.myjosh.in/profile/{}",       "err":"404",                          "status":404},
    # MISC
    {"name":"Instructables", "url":"https://www.instructables.com/member/{}/", "err":"404",                          "status":404},
    {"name":"WikiData",      "url":"https://www.wikidata.org/wiki/User:{}",    "err":"404",                          "status":404},
    {"name":"Clubhouse",     "url":"https://www.joinclubhouse.com/@{}",        "err":"404",                          "status":404},
    {"name":"Trakt.tv",      "url":"https://trakt.tv/users/{}",                "err":"404",                          "status":404},
    {"name":"AniList",       "url":"https://anilist.co/user/{}",               "err":"404",                          "status":404},
]

COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","dev","staging","test","api",
    "app","mobile","m","admin","dashboard","portal","blog","shop","store","cdn","media",
    "assets","static","img","images","video","news","support","help","docs","wiki","forum",
    "community","beta","alpha","old","new","v2","v3","vpn","gateway","proxy","secure",
    "login","auth","sso","id","account","accounts","my","cloud","files","backup","db",
    "database","sql","redis","cache","search","analytics","tracking","metrics","monitor",
    "status","health","internal","corp","intranet","office","hr","finance","api2","api3",
    "stage","uat","prod","sandbox","demo","preview","web","mail2","ns1","ns2","mx","mx1",
    "smtp2","autodiscover","autoconfig","cpanel","whm","plesk","ftp2","sftp","ssh","git",
    "jenkins","ci","jira","grafana","kibana","elastic","mysql","rabbitmq","ns3","pay",
    "payment","checkout","cart","order","invoice","billing","crm","erp","hr","sales",
    "marketing","dl","download","upload","cdn2","s3","bucket","media2","img2","photo",
    "video2","live","stream","rtmp","ws","wss","websocket","socket","io","push","notify",
    "notification","alert","report","reports","data","analytics2","bi","dashboard2",
    "admin2","control","manage","manager","panel","control","ops","devops","build","deploy",
]

INTERESTING_PATHS = [
    "/.env","/.env.local","/.env.production","/.env.backup","/.env.dev","/.env.example",
    "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG","/.gitignore",
    "/.htaccess","/.htpasswd","/config.json","/config.yaml","/config.yml","/settings.json",
    "/swagger.json","/swagger.yaml","/openapi.json","/openapi.yaml","/api-docs",
    "/graphql","/graphiql","/__graphql","/graphql/playground",
    "/robots.txt","/sitemap.xml","/.well-known/security.txt","/.well-known/jwks.json",
    "/package.json","/composer.json","/wp-admin/","/wp-login.php","/wp-config.php",
    "/wp-json/wp/v2/users","/admin/","/administrator/","/login","/dashboard","/panel",
    "/backup.zip","/backup.sql","/dump.sql","/database.sql","/db.sql",
    "/debug","/phpinfo.php","/info.php","/_debug","/server-status","/server-info",
    "/.DS_Store","/_profiler","/api/v1/users","/api/v1/admin","/v1/health","/health",
    "/status","/ping","/actuator","/actuator/health","/actuator/env","/actuator/mappings",
    "/metrics","/prometheus","/trace","/logfile","/console","/h2-console","/jolokia",
    "/.idea/workspace.xml","/.vscode/settings.json","/crossdomain.xml",
    "/upload","/uploads","/file","/files","/media","/download","/downloads","/temp","/tmp",
    "/telescope","/horizon","/nova","/sanctum/csrf-cookie",
]

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 69:"TFTP",
    80:"HTTP", 110:"POP3", 135:"MSRPC", 139:"NetBIOS-SMB", 143:"IMAP",
    389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS", 587:"SMTP-TLS",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 1521:"Oracle", 2082:"cPanel",
    2083:"cPanel-SSL", 2375:"Docker", 2376:"Docker-TLS", 3000:"Dev-Server",
    3306:"MySQL", 3389:"RDP", 5000:"Flask/Dev", 5432:"PostgreSQL",
    5900:"VNC", 5984:"CouchDB", 6379:"Redis", 7474:"Neo4j", 8000:"Dev",
    8080:"HTTP-Alt", 8086:"InfluxDB", 8443:"HTTPS-Alt", 8888:"Jupyter",
    9000:"PHP-FPM/SonarQube", 9090:"Prometheus", 9200:"Elasticsearch",
    9300:"Elasticsearch-Cluster", 11211:"Memcached", 27017:"MongoDB",
    50070:"Hadoop", 61616:"ActiveMQ",
}

HIGH_RISK_PORTS = {
    23:"⚠ TELNET — Unencrypted remote access!", 21:"⚠ FTP — Unencrypted file transfer!",
    3389:"⚠ RDP EXPOSED — Remote Desktop vulnerable!", 6379:"⚠ REDIS EXPOSED — Often no auth!",
    27017:"⚠ MONGODB EXPOSED — Often no auth!", 9200:"⚠ ELASTICSEARCH EXPOSED!",
    5984:"⚠ COUCHDB EXPOSED!", 11211:"⚠ MEMCACHED EXPOSED!",
    2375:"⚠ DOCKER API EXPOSED — Critical!", 5900:"⚠ VNC EXPOSED — Remote screen!",
    2082:"⚠ cPanel EXPOSED!", 445:"⚠ SMB EXPOSED — EternalBlue risk!",
    1433:"⚠ MSSQL EXPOSED!", 5432:"⚠ PostgreSQL EXPOSED!", 3306:"⚠ MySQL EXPOSED!",
    8888:"⚠ Jupyter Notebook — Often no auth!", 50070:"⚠ Hadoop Admin EXPOSED!",
}

CMS_SIGNATURES = {
    "WordPress":["wp-content","wp-includes","wp-json","xmlrpc.php"],
    "Drupal":["sites/default","Drupal.settings","X-Generator: Drupal"],
    "Joomla":["components/com_","Joomla!"],
    "Shopify":["cdn.shopify.com","myshopify.com"],
    "Next.js":["/_next/","__NEXT_DATA__"],
    "Nuxt.js":["/_nuxt/","__NUXT__"],
    "React":["react.production.min.js","__reactFiber"],
    "Vue.js":["vue.runtime.min.js","__vue__"],
    "Angular":["ng-version=","angular.min.js"],
    "Laravel":["laravel_session","XSRF-TOKEN"],
    "Django":["csrfmiddlewaretoken","csrftoken"],
    "Rails":["_rails-root","ActionController"],
    "ASP.NET":["X-Powered-By: ASP.NET","__VIEWSTATE"],
    "PHP":["X-Powered-By: PHP","PHPSESSID"],
    "Nginx":["nginx"],
    "Apache":["Apache","mod_"],
    "Cloudflare":["cf-ray","CF-Cache-Status"],
    "AWS CloudFront":["X-Amz-Cf-Id","CloudFront"],
    "Vercel":["x-vercel-id"],
    "Netlify":["x-nf-request-id"],
    "Firebase":["firebaseapp.com","firebaseio.com"],
    "Stripe":["js.stripe.com"],
    "Bootstrap":["bootstrap.min.css"],
    "jQuery":["jquery.min.js"],
    "Tailwind CSS":["tailwindcss"],
    "Google Analytics":["google-analytics.com","gtag("],
}

# ══════════════════════════════════════════════════════════════════════════════
# CORE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════
def ua():
    global _ua_i
    u = USER_AGENTS[_ua_i % len(USER_AGENTS)]; _ua_i += 1; return u

def hdrs(extra=None):
    h = {"User-Agent": ua(), "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive", "DNT": "1"}
    if extra: h.update(extra)
    return h

def safe_get(url, timeout=12, extra=None, params=None, allow_redirects=True):
    try:
        return requests.get(url, timeout=timeout, headers=hdrs(extra),
                            params=params, verify=False, allow_redirects=allow_redirects)
    except Exception:
        return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def safe_slug(text):
    text = re.sub(r'https?://', '', str(text))
    text = re.sub(r'[^\w\-]', '_', text)
    return text.strip('_')[:80]

def status_badge(code):
    if code < 300:   return f"[bold green]{code}[/bold green]"
    if code < 400:   return f"[bold yellow]{code}[/bold yellow]"
    if code < 500:   return f"[bold red]{code}[/bold red]"
    return f"[dim]{code}[/dim]"

def section(t):
    console.print()
    console.print(Rule(f"[bold cyan]{t}[/bold cyan]", style="cyan"))

def ok(m):   console.print(f"  [bold green]✓[/bold green]  {m}")
def warn(m): console.print(f"  [bold yellow]⚠[/bold yellow]  {m}")
def err(m):  console.print(f"  [bold red]✗[/bold red]  {m}")
def info(m): console.print(f"  [cyan]→[/cyan]  {m}")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1: PHONE INTELLIGENCE (Enhanced)
# ══════════════════════════════════════════════════════════════════════════════
def phone_parse_core(raw, default_region="IN"):
    result = {"input": raw, "valid": False}
    if not PHONE_LIB:
        result["error"] = "phonenumbers library not installed"; return result
    try:
        p = ph_parse(raw, default_region)
    except Exception as e:
        result["error"] = str(e); return result

    nt = number_type(p)
    type_map = {
        PhoneNumberType.FIXED_LINE:           ("FIXED LINE",    "🏢", "Landline"),
        PhoneNumberType.MOBILE:               ("MOBILE",        "📱", "Mobile SIM"),
        PhoneNumberType.FIXED_LINE_OR_MOBILE: ("FIXED/MOBILE",  "📲", "Either"),
        PhoneNumberType.TOLL_FREE:            ("TOLL FREE",     "📞", "Free to call"),
        PhoneNumberType.PREMIUM_RATE:         ("PREMIUM RATE",  "💸", "Charges caller!"),
        PhoneNumberType.VOIP:                 ("VOIP",          "🌐", "Internet — fraud risk"),
        PhoneNumberType.PERSONAL_NUMBER:      ("PERSONAL",      "👤", "Follows subscriber"),
        PhoneNumberType.UAN:                  ("ENTERPRISE",    "🏛", "Enterprise"),
        PhoneNumberType.UNKNOWN:              ("UNKNOWN",       "❓", "Undetermined"),
    }
    ti = type_map.get(nt, ("UNKNOWN", "❓", "Undetermined"))
    region  = region_code_for_number(p)
    carrier = ph_carrier.name_for_number(p, "en") or "Unknown"
    geo     = geocoder.description_for_number(p, "en") or "Unknown"

    result.update({
        "parsed": p, "valid": is_valid_number(p), "possible": is_possible_number(p),
        "e164":          format_number(p, PhoneNumberFormat.E164),
        "international": format_number(p, PhoneNumberFormat.INTERNATIONAL),
        "national":      format_number(p, PhoneNumberFormat.NATIONAL),
        "rfc3966":       format_number(p, PhoneNumberFormat.RFC3966),
        "country_code":  p.country_code, "national_num": str(p.national_number),
        "region": region, "carrier": carrier, "geo": geo,
        "timezones": list(ph_tz.time_zones_for_number(p)),
        "line_type": ti[0], "line_icon": ti[1], "line_desc": ti[2],
    })

    signals = []
    if nt == PhoneNumberType.VOIP:         signals.append(("HIGH", "VOIP number — untraceable, common in cyber fraud"))
    if nt == PhoneNumberType.PREMIUM_RATE: signals.append(("HIGH", "Premium rate — victim charged for calling back"))
    if nt == PhoneNumberType.TOLL_FREE:    signals.append(("MED",  "Toll-free — commonly spoofed in scams"))
    if any(v in carrier.lower() for v in VOIP_PROVIDERS):
        signals.append(("HIGH", f"Carrier is known VOIP provider: {carrier}"))
    if region == "IN":
        d = re.sub(r'\D', '', result["national"])
        for pfx, note in FRAUD_PATTERNS_IN.items():
            if d.startswith(pfx): signals.append(("HIGH", f"Series {pfx}XXXXXXX — {note}"))
    result["fraud_signals"] = signals
    return result

def phone_carrier_db(core):
    region   = core.get("region", "")
    national = re.sub(r'\D', '', core.get("national", ""))
    result   = {"carrier": "", "circle": "", "type": "", "source": "TRAI Prefix DB", "ported_hint": False}
    if region == "IN" and len(national) == 10:
        p4 = national[:4]
        if p4 in INDIA_PREFIXES:
            c, circle, ntype = INDIA_PREFIXES[p4]
            result.update({"carrier": c, "circle": circle, "type": ntype})
        elif national[0] in "678":
            result.update({"carrier": "Reliance Jio (likely)", "circle": "Various", "type": "4G/5G"})
        elif national[:2] == "94":
            result.update({"carrier": "BSNL (likely)", "type": "2G/3G"})
        lib_c = core.get("carrier", "").strip().lower()
        db_c  = result.get("carrier", "").replace("(likely)", "").strip().lower()
        if lib_c and db_c and lib_c.split()[0] != db_c.split()[0] and lib_c not in ("unknown", ""):
            result["ported_hint"] = True
            result["ported_note"] = f"Prefix DB → '{result['carrier']}' vs phonenumbers lib → '{core['carrier']}' → LIKELY SIM PORTED (MNP)"
    return result

def phone_lookup_numlookup(e164):
    r = safe_get(f"https://api.numlookupapi.com/v1/info/{urllib.parse.quote(e164)}")
    if r and r.ok:
        try:
            d = r.json()
            return {"source": "NumLookupAPI", "valid": d.get("valid"), "carrier": d.get("carrier", ""),
                    "line_type": d.get("line_type", ""), "location": d.get("location", ""),
                    "country": d.get("country_name", "")}
        except: pass
    return {}

def phone_check_whatsapp(e164):
    number = e164.replace("+", "").replace(" ", "")
    result = {"platform": "WhatsApp", "url": f"https://wa.me/{number}", "found": None}
    r = safe_get(f"https://api.whatsapp.com/send?phone={number}", timeout=10)
    if r:
        text = r.text.lower()
        if "continue to chat" in text or "open whatsapp" in text:
            result.update({"status": "[bold green]✓ REGISTERED[/bold green]", "found": True})
        elif "invalid" in text or "not valid" in text:
            result.update({"status": "[red]NOT REGISTERED[/red]", "found": False})
        else:
            result.update({"status": "[yellow]POSSIBLY REGISTERED (check manually)[/yellow]", "found": None})
    else:
        result["status"] = "[dim]Timeout[/dim]"
    return result

def phone_check_telegram(e164):
    number = e164.replace("+", "")
    result = {"platform": "Telegram", "url": f"https://t.me/+{number}", "found": False}
    r = safe_get(f"https://t.me/+{number}", timeout=8)
    if r:
        text = r.text.lower()
        if "tgme_page_title" in text or "send message" in text or "join group" in text:
            result["found"]  = True
            result["status"] = "[bold green]✓ PUBLIC PROFILE FOUND[/bold green]"
            m = re.search(r'<div class="tgme_page_title"[^>]*>(.*?)</div>', r.text, re.S)
            if m: result["name"] = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        else:
            result["status"] = "[dim]No public Telegram profile[/dim]"
    return result

def phone_check_signal(e164):
    """Signal doesn't have public profiles but we check the link"""
    number = e164.replace("+", "")
    url = f"https://signal.me/#p/+{number}"
    return {"platform": "Signal", "url": url, "status": "[dim]Check manually[/dim]",
            "note": "Signal has no public API — visit link manually"}

def phone_scrape_shouldianswer(national, region):
    result = {"source": "ShouldIAnswer", "reports": 0, "rating": "", "comments": [], "fraud_keywords": []}
    digits  = re.sub(r'\D', '', national)
    domains = {"IN": "shouldianswer.net", "US": "shouldianswer.com", "GB": "shouldianswer.co.uk"}
    base    = domains.get(region, "shouldianswer.com")
    r = safe_get(f"https://www.{base}/phone-number/{digits}", timeout=10)
    if not r or not r.ok: return result
    soup = BeautifulSoup(r.text, "html.parser")
    m = re.search(r'(\d+)\s+(?:review|report|rating|comment)', r.text, re.I)
    if m: result["reports"] = int(m.group(1))
    for el in soup.find_all(class_=re.compile(r'rating|danger|safe|status', re.I))[:2]:
        txt = el.get_text(strip=True)[:80]
        if txt: result["rating"] = txt; break
    for el in soup.find_all(class_=re.compile(r'comment|review|post', re.I))[:3]:
        txt = el.get_text(strip=True)[:150]
        if len(txt) > 20 and "cookie" not in txt.lower(): result["comments"].append(txt)
    fwords = ["scam", "fraud", "cheat", "fake", "spam", "criminal", "police", "cyber", "threat", "loan", "sextortion", "blackmail"]
    result["fraud_keywords"] = [w for w in fwords if w in r.text.lower()]
    return result

def phone_scrape_800notes(national):
    result = {"source": "800notes.com", "reports": 0, "summary": "", "comments": []}
    digits = re.sub(r'\D', '', national)
    if len(digits) == 11 and digits[0] == '1': digits = digits[1:]
    if len(digits) != 10: return result
    fmt = f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    r = safe_get(f"https://800notes.com/Phone.aspx/{fmt}", timeout=10)
    if not r or not r.ok: return result
    soup = BeautifulSoup(r.text, "html.parser")
    meta = soup.find("meta", {"name": "description"})
    if meta and meta.get("content"): result["summary"] = meta["content"][:200]
    posts = soup.find_all(class_=re.compile(r'post|comment', re.I))
    result["reports"] = len(posts)
    for p in posts[:3]:
        txt = p.get_text(strip=True)[:150]
        if len(txt) > 20: result["comments"].append(txt)
    return result

def phone_scrape_callerhunt(national):
    result = {"source": "CallerHunt.in", "name": "", "reports": 0, "fraud_keywords": []}
    digits = re.sub(r'\D', '', national)
    r = safe_get(f"https://www.callerhunt.in/{digits}", timeout=8)
    if r and r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        h1 = soup.find("h1")
        if h1: result["name"] = h1.get_text(strip=True)[:60]
        m = re.search(r'(\d+)\s+(?:report|complaint)', r.text, re.I)
        if m: result["reports"] = int(m.group(1))
        fwords = ["scam", "fraud", "spam", "fake", "cheat", "criminal"]
        result["fraud_keywords"] = [w for w in fwords if w in r.text.lower()]
    return result

def phone_scrape_spamcalls(bare):
    result = {"source": "SpamCalls.net", "rating": "", "details": ""}
    r = safe_get(f"https://www.spamcalls.net/en/number/{bare}", timeout=8)
    if r and r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        for el in soup.find_all(class_=re.compile(r'rating|danger|safe', re.I))[:1]:
            result["rating"] = el.get_text(strip=True)[:60]
        for el in soup.find_all("p")[:3]:
            txt = el.get_text(strip=True)[:150]
            if len(txt) > 20: result["details"] = txt; break
    return result

def phone_scrape_truecaller(bare, region):
    result = {"source": "Truecaller (page meta)", "found": False, "name": "", "status": ""}
    url = f"https://www.truecaller.com/search/{region.lower()}/{bare}"
    r = safe_get(url, extra={"Referer": "https://www.truecaller.com/"}, timeout=10)
    if r and r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc  = soup.find("meta", property="og:description")
        if og_title and og_title.get("content"):
            ct = og_title["content"]
            if bare.replace("+", "") not in ct.replace(" ", "") and len(ct) > 2:
                result.update({"found": True, "name": ct, "status": f"Name: {ct}"})
        if og_desc and og_desc.get("content"):
            result["desc"] = og_desc["content"][:120]
        if not result["found"]: result["status"] = "Not found / private"
    return result

def phone_scrape_whocalledindia(national):
    result = {"source": "WhoCalledIndia", "name": "", "reports": 0}
    digits = re.sub(r'\D', '', national)
    r = safe_get(f"https://www.whocalledindia.in/{digits}", timeout=8)
    if r and r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        h1 = soup.find("h1")
        if h1: result["name"] = h1.get_text(strip=True)[:60]
        m = re.search(r'(\d+)\s+(?:report|complaint|user)', r.text, re.I)
        if m: result["reports"] = int(m.group(1))
    return result

def phone_scrape_eyecon(national):
    result = {"source": "Eyecon.mobi", "name": ""}
    digits = re.sub(r'\D', '', national)
    r = safe_get(f"https://www.eyecon.mobi/phone-number-lookup/{digits}", timeout=8)
    if r and r.ok:
        soup = BeautifulSoup(r.text, "html.parser")
        for el in soup.find_all(["h1", "h2"])[:2]:
            txt = el.get_text(strip=True)[:60]
            if len(txt) > 3 and txt.lower() not in ["search", "lookup", "phone"]:
                result["name"] = txt; break
    return result

def phone_check_upi_hints(national, region):
    """Check if phone has UPI associations (India only) — public hints only"""
    if region != "IN": return {}
    digits = re.sub(r'\D', '', national)
    result = {"source": "UPI Hint Scan", "hints": [], "upi_ids_to_check": []}
    # Common UPI handle patterns for Indian numbers
    common_handles = ["okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "paytm",
                      "apl", "juspay", "gpay", "phonepe", "upi", "sbi"]
    possible_upis = [f"{digits}@{h}" for h in common_handles[:5]]
    result["upi_ids_to_check"] = possible_upis
    result["hints"].append(f"Scan these UPI IDs on PhonePe/GPay/Paytm to confirm name linkage")
    result["hints"].append(f"Check: {digits}@paytm, {digits}@ybl, {digits}@oksbi")
    return result

def phone_make_dorks(core):
    e164     = core.get("e164", "")
    intl     = core.get("international", "")
    national = core.get("national", "")
    bare     = e164.replace("+", "")
    region   = core.get("region", "")
    g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    is_in = region == "IN"
    dorks = {
        "🔍 Identity Search": [
            (f'"{intl}"', g(f'"{intl}"')),
            (f'"{national}"', g(f'"{national}"')),
            (f'"{bare}"', g(f'"{bare}"')),
        ],
        "🚨 Fraud & Complaints": [
            (f'"{national}" scam/fraud/cheat', g(f'"{national}" scam OR fraud OR cheat OR complaint')),
            (f'"{national}" cybercrime/FIR',   g(f'"{national}" cybercrime OR police OR FIR OR arrested')),
            (f'Truecaller lookup',              f"https://www.truecaller.com/search/{region.lower()}/{bare}"),
            (f'NumLookupAPI',                   f"https://api.numlookupapi.com/v1/info/{e164}"),
        ],
        "📱 Social Media": [
            ("Facebook search",  g(f'"{national}" site:facebook.com')),
            ("Instagram",        g(f'"{national}" site:instagram.com')),
            ("LinkedIn",         g(f'"{national}" site:linkedin.com')),
            ("Telegram",         g(f'"{national}" site:t.me OR telegram')),
            ("Twitter/X",        g(f'"{national}" site:twitter.com OR site:x.com')),
        ],
        "📒 Indian Directories": [
            ("JustDial",   g(f'"{national}" site:justdial.com')),
            ("IndiaMART",  g(f'"{national}" site:indiamart.com')),
            ("OLX/Quikr",  g(f'"{national}" site:olx.in OR site:quikr.com')),
            ("Sulekha",    g(f'"{national}" site:sulekha.com')),
            ("CallerHunt", f"https://www.callerhunt.in/{re.sub(r'[^0-9]', '', national)}"),
        ] if is_in else [
            ("YellowPages", g(f'"{national}" site:yellowpages.com')),
            ("Yelp",        g(f'"{national}" site:yelp.com')),
            ("Whitepages",  g(f'"{national}" site:whitepages.com')),
        ],
        "📄 Leaks & Docs": [
            ("Pastebin",     g(f'"{national}" site:pastebin.com')),
            ("GitHub",       g(f'"{e164}" site:github.com')),
            ("PDF files",    g(f'"{national}" filetype:pdf')),
            ("Spreadsheets", g(f'"{national}" filetype:xlsx OR filetype:csv')),
        ],
        "🔎 Reverse Lookup Sites": [
            ("ShouldIAnswer", f"https://www.shouldianswer.com/phone-number/{re.sub(r'[^0-9]', '', national)}"),
            ("SpamCalls.net", f"https://www.spamcalls.net/en/number/{bare}"),
            ("Eyecon.mobi",   f"https://www.eyecon.mobi/phone-number-lookup/{re.sub(r'[^0-9]', '', national)}"),
            ("CallerName",    f"https://callername.com/{re.sub(r'[^0-9]', '', national)}"),
        ],
        "🔏 Cybercrime Portals": [
            ("Cybercrime.gov.in", "https://cybercrime.gov.in") if is_in else ("IC3.gov", "https://ic3.gov"),
            ("TRAI DND Check",    "https://www.trai.gov.in/dnd_info") if is_in else ("FTC Report", "https://reportfraud.ftc.gov"),
        ],
    }
    return dorks

def phone_risk_score(core, cdb, spams, social):
    score, reasons = 0, []
    lt = core.get("line_type", "")
    if "VOIP"    in lt: score += 35; reasons.append("+35  VOIP — untraceable, #1 cyber fraud vector")
    if "PREMIUM" in lt: score += 25; reasons.append("+25  Premium rate — charges victim on callback")
    if "TOLL"    in lt: score += 10; reasons.append("+10  Toll-free — spoofing risk")
    if any(v in core.get("carrier", "").lower() for v in VOIP_PROVIDERS):
        score += 20; reasons.append(f"+20  VOIP carrier: {core['carrier']}")
    if cdb.get("ported_hint"):
        score += 10; reasons.append("+10  SIM porting (MNP) detected")
    for lvl, sig in core.get("fraud_signals", []):
        pts = 25 if lvl == "HIGH" else 10
        score += pts; reasons.append(f"+{pts}  {sig}")
    total_rep = 0
    for r in spams:
        if not isinstance(r, dict): continue
        rep = r.get("reports", 0)
        total_rep += rep
        kws = r.get("fraud_keywords", [])
        if kws: score += 15; reasons.append(f"+15  Fraud keywords on {r.get('source', '')[:20]}: {kws[:3]}")
    if total_rep > 50:   score += 25; reasons.append(f"+25  {total_rep} total community spam reports")
    elif total_rep > 10: score += 12; reasons.append(f"+12  {total_rep} spam reports")
    elif total_rep > 0:  score += 5;  reasons.append(f"+5   {total_rep} spam reports")
    wa = next((s for s in social if s.get("platform") == "WhatsApp"), {})
    if wa.get("found") is False and core.get("region") == "IN":
        score += 8; reasons.append("+8   No WhatsApp — possible burner/temporary SIM")
    score = min(100, max(0, score))
    if score >= 75:   lv, col, em = "HIGH RISK — LIKELY FRAUD",       "red",    "🚨"
    elif score >= 50: lv, col, em = "MEDIUM-HIGH RISK — SUSPICIOUS",  "red",    "⚠ "
    elif score >= 30: lv, col, em = "MEDIUM RISK",                    "yellow", "⚠ "
    elif score >= 10: lv, col, em = "LOW RISK",                       "yellow", "ℹ "
    else:             lv, col, em = "MINIMAL RISK — LOOKS CLEAN",     "green",  "✓ "
    return {"score": score, "level": lv, "color": col, "emoji": em, "reasons": reasons}

def run_phone_intel(number_str, region="IN"):
    all_data = {"input": number_str, "ts": datetime.now().isoformat()}

    console.print(Panel(
        f"[bold white]Number:[/bold white]  [bold cyan]{number_str}[/bold cyan]\n"
        f"[bold white]Region:[/bold white]  [cyan]{region}[/cyan]\n"
        f"[bold white]Engine:[/bold white]  [bold green]SpiderFoot-class · 10+ Sources · Zero API Keys[/bold green]",
        title="[bold yellow]📞  PHONE INTELLIGENCE  v3.0 — Police Edition[/bold yellow]",
        border_style="yellow", padding=(1, 3)
    ))

    # ── Core parse ─────────────────────────────────────────────────────────────
    section("① Core Analysis  (phonenumbers library — offline)")
    core = phone_parse_core(number_str, region)
    all_data["core"] = core
    if core.get("error"):
        err(f"Parse error: {core['error']}"); return all_data

    t = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), border_style="cyan")
    t.add_column("Field", style="bold cyan", width=22)
    t.add_column("Value", style="white")
    for k, v in [
        ("E.164",           core["e164"]),
        ("International",   core["international"]),
        ("National",        core["national"]),
        ("Country/Region",  f"{core['region']}  (+{core['country_code']})"),
        ("Carrier",         core["carrier"]),
        ("Geographic Area", core["geo"]),
        ("Line Type",       f"{core['line_icon']} {core['line_type']} — {core['line_desc']}"),
        ("Timezones",       "  ".join(core["timezones"])),
        ("Valid",           "[bold green]✓ YES[/bold green]" if core["valid"] else "[bold red]✗ NO[/bold red]"),
    ]:
        if v: t.add_row(k, str(v))
    console.print(t)

    for lvl, sig in core.get("fraud_signals", []):
        col = "bold red" if lvl == "HIGH" else "bold yellow"
        console.print(f"  [{col}]🚨 [{lvl}] {sig}[/{col}]")

    # ── Carrier DB ─────────────────────────────────────────────────────────────
    section("② Carrier Database  (TRAI/FCC Prefix Intelligence — offline)")
    cdb = phone_carrier_db(core)
    all_data["carrier_db"] = cdb
    ct = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), border_style="cyan")
    ct.add_column("Field", style="bold cyan", width=22)
    ct.add_column("Value", style="white")
    ct.add_row("Carrier (prefix DB)", cdb.get("carrier", "—") or "—")
    ct.add_row("Circle / State",      cdb.get("circle", "—") or "—")
    ct.add_row("Network Type",        cdb.get("type", "—") or "—")
    ct.add_row("Source",              cdb.get("source", "—"))
    console.print(ct)
    if cdb.get("ported_hint"):
        console.print(f"  [bold red]🔄 POSSIBLE SIM PORTING (MNP) DETECTED[/bold red]")
        console.print(f"  [dim]{cdb.get('ported_note', '')}[/dim]")

    # ── Online presence checks ─────────────────────────────────────────────────
    section("③ Social & Messaging Presence  (WhatsApp · Telegram · Signal)")
    social = []
    e164    = core["e164"]
    bare    = e164.replace("+", "")
    national = core["national"]

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30),
                  TimeElapsedColumn(), console=console) as prog:
        soc_checks = [
            ("WhatsApp",  lambda: phone_check_whatsapp(e164)),
            ("Telegram",  lambda: phone_check_telegram(e164)),
            ("Signal",    lambda: phone_check_signal(e164)),
        ]
        task = prog.add_task("[cyan]Checking...", total=len(soc_checks))
        for name, fn in soc_checks:
            prog.update(task, description=f"[cyan]→ {name}...")
            try: social.append(fn())
            except: pass
            prog.advance(task)

    all_data["social"] = social
    sot = Table(box=box.ROUNDED, padding=(0, 2), border_style="cyan")
    sot.add_column("Platform", style="bold cyan", width=14)
    sot.add_column("Status",   width=50)
    sot.add_column("Name / Handle", style="bold green")
    for s in social:
        sot.add_row(s.get("platform", "?"), str(s.get("status", ""))[:50], s.get("name", "")[:30])
    console.print(sot)

    # ── Spam databases ─────────────────────────────────────────────────────────
    section("④ Public Spam & Fraud Databases  (8+ Sources — No Login Required)")
    spam_results = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30),
                  TimeElapsedColumn(), console=console) as prog:
        spam_checks = [
            ("ShouldIAnswer",    lambda: phone_scrape_shouldianswer(national, core["region"])),
            ("800notes",         lambda: phone_scrape_800notes(national)),
            ("SpamCalls.net",    lambda: phone_scrape_spamcalls(bare)),
            ("Truecaller Page",  lambda: phone_scrape_truecaller(bare, core["region"])),
            ("Eyecon.mobi",      lambda: phone_scrape_eyecon(national)),
            ("CallerHunt.in",    lambda: phone_scrape_callerhunt(national)),
            ("WhoCalledIndia",   lambda: phone_scrape_whocalledindia(national)),
            ("NumLookupAPI",     lambda: phone_lookup_numlookup(e164)),
        ]
        task = prog.add_task("[cyan]Scraping...", total=len(spam_checks))
        for name, fn in spam_checks:
            prog.update(task, description=f"[cyan]→ {name}...")
            try:
                res = fn()
                if isinstance(res, list): spam_results.extend(res)
                elif res: spam_results.append(res)
            except: pass
            prog.advance(task)

    all_data["spam_checks"] = spam_results

    st = Table(box=box.ROUNDED, padding=(0, 2), border_style="red")
    st.add_column("Database",      style="bold cyan",  width=22)
    st.add_column("Reports",       width=9)
    st.add_column("Name / Status", style="bold white", width=32)
    st.add_column("Fraud Keywords", style="bold red")
    for r in spam_results:
        if not isinstance(r, dict): continue
        name_s = (r.get("name") or r.get("rating") or r.get("status") or r.get("details") or "")
        rpts   = str(r.get("reports", "") or "")
        kws    = ", ".join(r.get("fraud_keywords", [])[:4])
        if r.get("found"): name_s = f"[green]{name_s}[/green]"
        st.add_row(r.get("source", "?")[:22], rpts, str(name_s)[:32], kws[:32])
    console.print(st)

    for r in spam_results:
        if not isinstance(r, dict): continue
        for comment in r.get("comments", [])[:2]:
            console.print(f"  [dim italic]💬 {r.get('source', '')} → \"{comment}\"[/dim italic]")

    # ── UPI hint (India) ───────────────────────────────────────────────────────
    if core.get("region") == "IN":
        section("⑤ UPI / Digital Payments Intelligence  (India)")
        upi = phone_check_upi_hints(national, core["region"])
        all_data["upi_hints"] = upi
        if upi:
            info(f"Suggested UPI IDs to probe on PhonePe / GPay / Paytm:")
            for uid in upi.get("upi_ids_to_check", [])[:8]:
                console.print(f"  [bold cyan]{uid}[/bold cyan]")
            for hint in upi.get("hints", []):
                info(hint)
            console.print()
            info("[bold yellow]Tip: Open PhonePe or Google Pay → 'Pay' → type UPI ID → shows registered name[/bold yellow]")

    # ── Dorks ──────────────────────────────────────────────────────────────────
    section("⑥ Investigation Links & Google Dorks  (100% Clickable)")
    dorks = phone_make_dorks(core)
    all_data["dorks"] = dorks
    for cat, items in dorks.items():
        console.print(f"\n  [bold yellow]{cat}[/bold yellow]")
        for label, url in items:
            console.print(f"    [dim]{label:<38}[/dim]  [cyan]{url[:120]}[/cyan]")

    # ── Risk score ─────────────────────────────────────────────────────────────
    section("⑦ Fraud Risk Assessment  (Multi-Signal Scoring Engine)")
    risk = phone_risk_score(core, cdb, spam_results, social)
    all_data["risk"] = risk
    filled = "█" * (risk["score"] // 5)
    empty  = "░" * (20 - risk["score"] // 5)
    col    = risk["color"]
    body = (f"[bold white]Score:[/bold white]  [{col}]{risk['score']} / 100[/{col}]\n"
            f"[{col}]{filled}{empty}[/{col}]\n\n"
            f"[bold white]Level:[/bold white]  [{col}]{risk['emoji']}  {risk['level']}[/{col}]")
    if risk["reasons"]:
        body += "\n\n[bold white]Evidence Chain:[/bold white]\n" + "\n".join(f"  {r}" for r in risk["reasons"])
    console.print(Panel(body, title="[bold yellow]Risk Score[/bold yellow]",
                        border_style=col, padding=(1, 3)))

    # ── Investigation checklist ────────────────────────────────────────────────
    section("⑧ Police Investigation Checklist")
    is_in = core.get("region") == "IN"
    steps = [
        "Click the dorks above → instant Google results",
        "Open Truecaller on phone → search number → real name often visible",
        "WhatsApp: check profile picture + 'About' text → reverse image search the photo",
        "Facebook: paste number in search bar → many accounts linked to phone",
        "Open PhonePe/GPay → Pay → type number → shows linked UPI name (India)" if is_in else "",
        "Check OLX/Quikr/IndiaMART → may have seller listings with name" if is_in else "Check Craigslist/OfferUp for listings",
        "Search '<number> fraud' on Google → check cybercrime complaint sites",
        "CallerHunt.in and WhoCalledIndia.in → check community reports" if is_in else "800notes.com → check reports",
        f"File complaint: https://cybercrime.gov.in" if is_in else "File IC3: https://ic3.gov",
        "Cross-pivot: use --pivot flag to auto-find linked emails/usernames",
    ]
    for i, s in enumerate(steps, 1):
        if s: console.print(f"  [bold cyan]{i}.[/bold cyan] {s}")

    return all_data


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2: EMAIL INTELLIGENCE (Enhanced)
# ══════════════════════════════════════════════════════════════════════════════
def email_smtp_probe(email):
    """SMTP VRFY/RCPT TO probe to verify email existence"""
    result = {"method": "SMTP Probe", "exists": None, "mx_host": "", "detail": ""}
    domain = email.split("@")[1] if "@" in email else ""
    if not domain: return result
    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
        result["mx_host"] = mx_host
        with smtplib.SMTP(mx_host, 25, timeout=8) as smtp:
            smtp.ehlo("probe.osintpro.local")
            code, _ = smtp.mail("probe@osintpro.local")
            code, _ = smtp.rcpt(email)
            if code == 250:
                result.update({"exists": True, "detail": "RCPT TO accepted — mailbox likely exists"})
            elif code == 550:
                result.update({"exists": False, "detail": "RCPT TO rejected — mailbox does not exist"})
            elif code == 421:
                result.update({"exists": None, "detail": "Server busy / rate limited"})
            else:
                result.update({"exists": None, "detail": f"SMTP response code: {code}"})
    except smtplib.SMTPConnectError:
        result["detail"] = "Cannot connect to MX — port 25 blocked (common)"
    except smtplib.SMTPRecipientsRefused:
        result.update({"exists": False, "detail": "Recipient refused by server"})
    except Exception as e:
        result["detail"] = f"Probe failed: {str(e)[:80]}"
    return result

def email_breach_check_hashes(email):
    """Check breaches via free APIs"""
    results = []
    # BreachDirectory.org free API
    try:
        r = safe_get(
            "https://breachdirectory.org/api",
            params={"func": "auto", "term": email},
            timeout=10
        )
        if r and r.ok:
            d = r.json()
            if d.get("result") and d["result"] != "0":
                results.append({"source": "BreachDirectory", "found": True, "count": d.get("result", "?"),
                                 "detail": "Email found in breach database"})
    except: pass

    # HIBP password k-anon check (no key needed, uses SHA-1 prefix)
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = sha1[:5]
        r = safe_get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        if r and r.ok:
            if sha1[5:] in r.text:
                results.append({"source": "HIBP PwnedPasswords", "found": True,
                                 "detail": "Email hash found in leaked password list"})
    except: pass

    return results

def email_gravatar_check(email):
    md5_hash = hashlib.md5(email.lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
    r = safe_get(url, timeout=6)
    has_gravatar = r and r.status_code == 200
    return {
        "found": has_gravatar,
        "url": f"https://www.gravatar.com/avatar/{md5_hash}",
        "profile": f"https://en.gravatar.com/{md5_hash}",
    }

def email_github_search(email):
    result = {"commits": 0, "repos": [], "username": ""}
    try:
        r = requests.get(
            f"https://api.github.com/search/commits?q=author-email:{email}&per_page=5",
            headers={"User-Agent": ua(), "Accept": "application/vnd.github.cloak-preview"},
            timeout=12
        )
        if r and r.ok:
            d = r.json()
            result["commits"] = d.get("total_count", 0)
            for item in d.get("items", [])[:5]:
                result["repos"].append({
                    "repo": item["repository"]["full_name"],
                    "msg": item["commit"]["message"][:60],
                    "sha": item["sha"][:8],
                })
                # Extract GitHub username from commit author
                if not result["username"]:
                    author = item.get("author", {})
                    if author: result["username"] = author.get("login", "")
    except: pass
    return result

def email_social_probes(email, username):
    """Check if email username exists on social platforms"""
    results = []
    # Gravatar (email hash)
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    r = safe_get(f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=5)
    if r and r.status_code == 200:
        results.append({"platform": "Gravatar", "url": f"https://en.gravatar.com/{md5}", "found": True})

    # Quick username checks on major platforms
    quick_sites = [
        ("GitHub",    f"https://github.com/{username}",             404),
        ("Twitter/X", f"https://x.com/{username}",                  404),
        ("Instagram", f"https://www.instagram.com/{username}/",     404),
        ("Reddit",    f"https://www.reddit.com/user/{username}/",   404),
    ]
    for platform, url, expected_err_code in quick_sites:
        try:
            resp = requests.get(url, timeout=6, headers=hdrs(), verify=False, allow_redirects=True)
            if resp and resp.status_code != expected_err_code and resp.status_code != 404:
                results.append({"platform": platform, "url": url, "found": True})
        except: pass
    return results

def run_email_intel(email):
    all_data = {"input": email, "ts": datetime.now().isoformat()}

    console.print(Panel(
        f"[bold white]Email:[/bold white]   [bold cyan]{email}[/bold cyan]\n"
        f"[bold white]Engine:[/bold white]  [bold green]SMTP Probe · Breach Check · Gravatar · GitHub · Social Links[/bold green]",
        title="[bold yellow]📧  EMAIL INTELLIGENCE  v3.0 — Police Edition[/bold yellow]",
        border_style="yellow", padding=(1, 3)
    ))

    # Validate format
    email_re = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    if not email_re.match(email):
        err(f"Invalid email format: {email}"); return all_data

    parts    = email.split("@")
    username = parts[0]
    domain   = parts[1]
    all_data.update({"username": username, "domain": domain})

    # ── Core info ──────────────────────────────────────────────────────────────
    section("① Email Structure Analysis")
    t = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), border_style="cyan")
    t.add_column("Check", style="bold cyan", width=24)
    t.add_column("Result", style="white")

    t.add_row("Email Address", email)
    t.add_row("Username Part", username)
    t.add_row("Domain Part",   domain)

    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    all_data["disposable"] = is_disposable
    t.add_row("Disposable?", "[bold red]🚨 YES — TEMPORARY MAIL[/bold red]" if is_disposable else "[green]No[/green]")

    free_providers = {"gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com",
                      "icloud.com","aol.com","ymail.com","live.com","msn.com","rediffmail.com",
                      "yahoo.in","yahoo.co.in"}
    is_free = domain.lower() in free_providers
    all_data["free_provider"] = is_free
    t.add_row("Provider Type",
              "[yellow]Free / Public[/yellow]" if is_free else "[green]Corporate / Custom domain[/green]")

    # MX records
    mx_ok = False
    try:
        mx_recs = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_list = sorted(mx_recs, key=lambda r: r.preference)
        mx_strs = [str(r.exchange).rstrip(".") for r in mx_list]
        all_data["mx_records"] = mx_strs
        mx_ok = True
        t.add_row("MX Records", "[green]✓ " + ", ".join(mx_strs[:2]) + "[/green]")
        # Identify email provider from MX
        mx_combined = " ".join(mx_strs).lower()
        if "google" in mx_combined or "gmail" in mx_combined:
            t.add_row("MX Provider", "[cyan]Google Workspace[/cyan]")
        elif "outlook" in mx_combined or "microsoft" in mx_combined:
            t.add_row("MX Provider", "[cyan]Microsoft 365[/cyan]")
        elif "protonmail" in mx_combined:
            t.add_row("MX Provider", "[cyan]ProtonMail[/cyan]")
        elif "zoho" in mx_combined:
            t.add_row("MX Provider", "[cyan]Zoho Mail[/cyan]")
    except Exception:
        all_data["mx_records"] = []
        t.add_row("MX Records", "[red]✗ No MX — cannot receive email[/red]")

    console.print(t)

    # ── SMTP probe ─────────────────────────────────────────────────────────────
    section("② SMTP Probe  (Direct mailserver verification)")
    with console.status("[cyan]SMTP probing mail server..."):
        smtp_result = email_smtp_probe(email)
    all_data["smtp_probe"] = smtp_result

    if smtp_result.get("exists") is True:
        console.print(f"  [bold green]✓ MAILBOX CONFIRMED EXISTING[/bold green]  — {smtp_result['detail']}")
    elif smtp_result.get("exists") is False:
        console.print(f"  [bold red]✗ MAILBOX DOES NOT EXIST[/bold red]  — {smtp_result['detail']}")
    else:
        console.print(f"  [yellow]? INCONCLUSIVE[/yellow]  — {smtp_result['detail']}")

    if smtp_result.get("mx_host"):
        info(f"MX Host probed: {smtp_result['mx_host']}")

    # ── Breach check ──────────────────────────────────────────────────────────
    section("③ Data Breach Intelligence  (BreachDirectory + HIBP Hash Check)")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30),
                  console=console) as prog:
        task = prog.add_task("[cyan]Checking breach databases...", total=1)
        breach_results = email_breach_check_hashes(email)
        prog.advance(task)
    all_data["breaches"] = breach_results

    if breach_results:
        for br in breach_results:
            console.print(f"  [bold red]🚨 BREACH FOUND: {br['source']} — {br['detail']}[/bold red]")
    else:
        console.print("  [green]✓ No breach hits via free hash-check APIs[/green]")
        info("For full HIBP breach list: https://haveibeenpwned.com (requires API key)")

    # ── Gravatar + social ──────────────────────────────────────────────────────
    section("④ Profile Photo & Social Presence  (Gravatar · GitHub · Social Platforms)")
    with console.status("[cyan]Checking social presence..."):
        grav   = email_gravatar_check(email)
        github = email_github_search(email)
        social = email_social_probes(email, username)
    all_data["gravatar"] = grav
    all_data["github"]   = github
    all_data["social_probes"] = social

    gt = Table(box=box.ROUNDED, padding=(0, 2), border_style="cyan")
    gt.add_column("Source",  style="bold cyan",  width=20)
    gt.add_column("Status",  width=20)
    gt.add_column("Detail",  style="dim")

    gt.add_row("Gravatar",
               "[green]✓ PHOTO FOUND[/green]" if grav["found"] else "[dim]No gravatar[/dim]",
               grav["url"] if grav["found"] else "")

    if github["commits"] > 0:
        gt.add_row("GitHub Commits", f"[green]✓ {github['commits']} commits[/green]",
                   f"Username: @{github['username']}" if github["username"] else "")
        for repo in github["repos"][:2]:
            console.print(f"  [dim]  → [{repo['sha']}] {repo['repo']}: {repo['msg']}[/dim]")
    else:
        gt.add_row("GitHub", "[dim]No public commits[/dim]", "")

    for s in social:
        if s.get("found"):
            gt.add_row(s["platform"], "[green]✓ PROFILE FOUND[/green]", s.get("url", ""))

    console.print(gt)

    if grav["found"]:
        console.print(f"\n  [bold yellow]🖼  Gravatar URL (reverse image search this!):[/bold yellow]")
        console.print(f"  [cyan]{grav['url']}[/cyan]")

    # ── Email permutations ─────────────────────────────────────────────────────
    section("⑤ Email Permutation Generator  (for cross-investigation)")
    perms = set()
    parts_u = re.split(r'[._\-]', username)
    if len(parts_u) >= 2:
        f, l = parts_u[0], parts_u[-1]
        for d in [domain, "gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]:
            perms.add(f"{f}.{l}@{d}")
            perms.add(f"{f}{l}@{d}")
            perms.add(f"{l}.{f}@{d}")
            perms.add(f"{f[0]}{l}@{d}")
            perms.add(f"{f}.{l[0]}@{d}")
            perms.add(f"{l}{f[0]}@{d}")
    all_data["permutations"] = list(perms)[:20]
    info(f"Generated {len(all_data['permutations'])} email permutations (saved to report)")
    for p in list(perms)[:6]:
        console.print(f"  [dim]{p}[/dim]")

    # ── Dorks ──────────────────────────────────────────────────────────────────
    section("⑥ Investigation Links & Google Dorks")
    g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    dorks = {
        "🔍 Identity": [
            (f'"{email}"',                     g(f'"{email}"')),
            (f'"{username}" identity',          g(f'"{username}" person OR profile OR name')),
            (f'"{email}" documents',            g(f'"{email}" filetype:pdf OR filetype:xlsx')),
        ],
        "🚨 Fraud": [
            (f'"{email}" scam/fraud',           g(f'"{email}" scam OR fraud OR complaint OR cheat')),
            (f'"{email}" cybercrime',           g(f'"{email}" cybercrime OR police OR FIR')),
        ],
        "👤 Social Media": [
            ("GitHub",    g(f'"{username}" site:github.com')),
            ("LinkedIn",  g(f'"{email}" site:linkedin.com')),
            ("Facebook",  g(f'"{email}" site:facebook.com')),
            ("Pastebin",  g(f'"{email}" site:pastebin.com')),
        ],
        "📄 Leaks & Data": [
            ("Pastebin", g(f'"{email}" site:pastebin.com')),
            ("GitHub",   g(f'"{email}" site:github.com')),
            ("Docs",     g(f'"{email}" filetype:pdf OR filetype:xls OR filetype:csv')),
        ],
        "🔏 Breach Check Tools": [
            ("HIBP",            f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"),
            ("DeHashed",        f"https://dehashed.com/search?query={urllib.parse.quote(email)}"),
            ("BreachDirectory", f"https://breachdirectory.org/?q={urllib.parse.quote(email)}"),
        ],
    }
    all_data["dorks"] = dorks
    for cat, items in dorks.items():
        console.print(f"\n  [bold yellow]{cat}[/bold yellow]")
        for label, url in items:
            console.print(f"    [dim]{label:<30}[/dim]  [cyan]{url[:120]}[/cyan]")

    return all_data


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3: USERNAME HUNT (200+ Sites — Sherlock Class)
# ══════════════════════════════════════════════════════════════════════════════
def run_username_hunt(username):
    all_data = {"username": username, "found": [], "not_found": [], "ts": datetime.now().isoformat()}

    console.print(Panel(
        f"[bold white]Target:[/bold white]   [bold cyan]@{username}[/bold cyan]\n"
        f"[bold white]Sites:[/bold white]    [cyan]{len(USERNAME_SITES)} platforms[/cyan]\n"
        f"[bold white]Engine:[/bold white]   [bold green]Sherlock-class · Concurrent · Zero API Keys[/bold green]",
        title="[bold yellow]👤  USERNAME HUNT  v3.0 — Police Edition[/bold yellow]",
        border_style="yellow", padding=(1, 3)
    ))

    found, not_found, errors = [], [], []

    def check_site(site):
        url = site["url"].format(username)
        err_text = site.get("err", "")
        try:
            r = requests.get(url, timeout=9, headers=hdrs(), allow_redirects=True, verify=False)
            if r and r.status_code not in [404, 410, 999]:
                if not err_text or err_text.lower() not in r.text.lower():
                    return site["name"], url, "FOUND", r.status_code
            return site["name"], url, "NOT_FOUND", r.status_code if r else 0
        except Exception:
            return site["name"], url, "ERROR", 0

    section("Hunting across 200+ platforms...")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=30),
                  TextColumn("[bold green]{task.completed}[/bold green]/[bold]{task.total}[/bold]"),
                  TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task(f"[cyan]@{username}", total=len(USERNAME_SITES))
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_site, s): s for s in USERNAME_SITES}
            for f in as_completed(futures):
                name, url, status, code = f.result()
                prog.advance(task)
                if   status == "FOUND":     found.append((name, url, code))
                elif status == "NOT_FOUND": not_found.append(name)
                else:                       errors.append(name)

    all_data["found"]     = [{"site": n, "url": u, "status": c} for n, u, c in found]
    all_data["not_found"] = not_found

    if found:
        console.print(f"\n[bold green]✓ Found on {len(found)} platform(s):[/bold green]")
        t = Table(box=box.ROUNDED, padding=(0, 2), border_style="green")
        t.add_column("Platform",     style="bold green", width=18)
        t.add_column("Status Code",  style="dim",        width=8)
        t.add_column("URL",          style="cyan")
        for name, url, code in sorted(found):
            t.add_row(name, str(code), url)
        console.print(t)
    else:
        warn("Username not found on any checked platforms")

    # Dorks for the username
    console.print(f"\n[bold yellow]🔍 Investigation Dorks for @{username}:[/bold yellow]")
    g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    dork_list = [
        (f'"{username}" profile',   g(f'"{username}" profile OR account OR bio')),
        (f'"{username}" real name', g(f'"{username}" "real name" OR "full name"')),
        (f'"{username}" location',  g(f'"{username}" location OR city OR country')),
        (f'"{username}" email',     g(f'"{username}" email OR contact OR DM')),
        (f'GitHub @{username}',     f"https://github.com/{username}"),
        (f'Telegram @{username}',   f"https://t.me/{username}"),
    ]
    all_data["dorks"] = dork_list
    for label, url in dork_list:
        console.print(f"  [dim]{label:<30}[/dim]  [cyan]{url[:120]}[/cyan]")

    console.print(f"\n[dim]Checked: {len(USERNAME_SITES)} | Found: {len(found)} | Not found: {len(not_found)} | Errors: {len(errors)}[/dim]")
    return all_data


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4: DOMAIN INTELLIGENCE (Enhanced)
# ══════════════════════════════════════════════════════════════════════════════
def domain_whois(domain):
    try:
        w = whois_lib.whois(domain)
        data = {
            "registrar":       str(w.registrar or ""),
            "creation_date":   str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "updated_date":    str(w.updated_date or ""),
            "name_servers":    list(set(str(ns).lower() for ns in (w.name_servers or []))),
            "status":          str(w.status or ""),
            "emails":          (list(set(w.emails)) if isinstance(w.emails, (list, set))
                                else [str(w.emails)] if w.emails else []),
            "org":             str(w.org or ""),
            "country":         str(w.country or ""),
            "dnssec":          str(getattr(w, 'dnssec', '') or ""),
        }
        try:
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd:
                age = (datetime.now() - cd).days
                data["domain_age_days"] = age
                if age < 30:  data["NEW_DOMAIN_WARNING"] = True
                if age < 180: data["YOUNG_DOMAIN_WARNING"] = True
        except Exception:
            pass
        return data
    except Exception as e:
        return {"error": str(e)}

def domain_dns(domain):
    results = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV", "DMARC", "DKIM", "SPF"]:
        try:
            qname = domain
            rtype_q = rtype
            if rtype == "DMARC":  qname = f"_dmarc.{domain}"; rtype_q = "TXT"
            elif rtype == "DKIM": qname = f"default._domainkey.{domain}"; rtype_q = "TXT"
            elif rtype == "SPF":  rtype_q = "TXT"
            answers = dns.resolver.resolve(qname, rtype_q, lifetime=5)
            if rtype == "SPF":
                spf = [str(r) for r in answers if "v=spf1" in str(r).lower()]
                if spf: results["SPF"] = spf
            else:
                results[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return results

def domain_headers_ssl(domain):
    headers_data = {}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        r = safe_get(url, allow_redirects=True)
        if r:
            headers_data = {
                "url": url, "status": r.status_code,
                "headers": dict(r.headers), "server": r.headers.get("Server", ""),
                "powered_by": r.headers.get("X-Powered-By", ""),
                "final_url": r.url, "html": r.text[:15000],
            }
            break

    ssl_data = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=8),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
            san  = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
            nb   = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            na   = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
            days_left = (na - datetime.now()).days
            ssl_data = {
                "subject":    dict(x[0] for x in cert.get("subject", [])),
                "issuer":     dict(x[0] for x in cert.get("issuer",  [])),
                "not_before": str(nb.date()), "not_after": str(na.date()),
                "days_left":  days_left, "san": san, "san_count": len(san),
                "self_signed": cert.get("issuer") == cert.get("subject"),
                "expired":    days_left < 0, "expiring_soon": 0 < days_left < 30,
            }
    except Exception as e:
        ssl_data = {"error": str(e)}
    return headers_data, ssl_data

def domain_security_headers(headers):
    checks = {
        "Strict-Transport-Security":    ("HSTS",            "red"),
        "Content-Security-Policy":      ("CSP",             "red"),
        "X-Frame-Options":              ("Anti-Clickjack",  "yellow"),
        "X-Content-Type-Options":       ("MIME-Sniff",      "yellow"),
        "Referrer-Policy":              ("Referrer Policy", "blue"),
        "Permissions-Policy":           ("Permissions",     "blue"),
    }
    h_lower = {k.lower(): v for k, v in headers.items()}
    results = {}
    for header, (label, sev) in checks.items():
        results[label] = {"header": header, "present": header.lower() in h_lower,
                          "value": h_lower.get(header.lower(), ""), "severity": sev}
    return results

def domain_wayback(domain):
    """Query Wayback Machine CDX API for archive history"""
    result = {"snapshots": 0, "first_seen": "", "last_seen": "", "urls": [], "changes": []}
    try:
        r = safe_get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": domain, "output": "json", "limit": 10,
                    "fl": "timestamp,statuscode,mimetype,urlkey", "collapse": "timestamp:6"},
            timeout=15
        )
        if r and r.ok:
            data = r.json()
            if len(data) > 1:
                rows = data[1:]  # Skip header row
                result["snapshots"] = len(rows)
                if rows:
                    result["first_seen"] = rows[-1][0][:8] if rows[-1] else ""
                    result["last_seen"]  = rows[0][0][:8] if rows[0] else ""
                result["urls"] = [f"https://web.archive.org/web/{r[0]}/{domain}" for r in rows[:5]]
    except Exception:
        pass

    # Also get total count
    try:
        r2 = safe_get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}", "output": "json", "limit": 1,
                    "fl": "timestamp", "showNumPages": "true"},
            timeout=10
        )
        if r2 and r2.ok:
            try:
                total = int(r2.text.strip())
                result["total_pages"] = total
            except: pass
    except: pass

    return result

def domain_otx(domain):
    """AlienVault OTX Threat Intelligence (free, no key needed)"""
    result = {"pulses": 0, "malicious": False, "categories": [], "tags": [], "whois": {}}
    try:
        r = safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                     extra={"X-OTX-API-KEY": ""}, timeout=12)
        if r and r.ok:
            d = r.json()
            result.update({
                "pulses":    d.get("pulse_info", {}).get("count", 0),
                "malicious": d.get("pulse_info", {}).get("count", 0) > 0,
                "categories": list(set(d.get("categories", []))),
                "tags":       d.get("tags", [])[:10],
            })
    except: pass

    # Passive DNS via HackerTarget
    try:
        r2 = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if r2 and r2.ok and "error" not in r2.text.lower():
            hosts = [line.split(",")[0] for line in r2.text.strip().splitlines() if line.strip()]
            result["hackertarget_hosts"] = hosts[:20]
    except: pass

    return result

def domain_subdomains(domain):
    subs = set()
    # crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r.ok:
            for entry in r.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain:
                        subs.add(n)
    except: pass
    # HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.ok and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts: subs.add(parts[0].strip())
    except: pass
    return sorted(subs)

def domain_brute_subs(domain, wordlist):
    found = []
    def check(sub):
        fqdn = f"{sub}.{domain}"
        ip = resolve_ip(fqdn)
        return (fqdn, ip) if ip else (None, None)
    with ThreadPoolExecutor(max_workers=60) as ex:
        for fqdn, ip in ex.map(check, wordlist):
            if fqdn: found.append((fqdn, ip))
    return sorted(found)

def domain_paths(base_url, paths):
    found = []
    def check(path):
        url = base_url.rstrip("/") + path
        r = safe_get(url, timeout=6)
        if r and r.status_code not in [404, 410]:
            return {"url": url, "status": r.status_code, "size": len(r.content), "path": path}
        return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check, p): p for p in paths}
        for f in as_completed(futures):
            result = f.result()
            if result: found.append(result)
    return sorted(found, key=lambda x: x["status"])

def domain_js_recon(base_url):
    results = {"endpoints": [], "secrets": {}, "js_files": [], "emails": [], "phones": [], "graphql": False}
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

    # Endpoints
    ep_pats = [
        r'["\'](/api/[a-zA-Z0-9_/.\-]+)["\']',
        r'["\']/(v\d+/[a-zA-Z0-9_/.\-]+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    eps = set()
    for pat in ep_pats:
        for m in re.findall(pat, all_js):
            if 3 < len(m) < 200: eps.add(m)
    results["endpoints"] = sorted(eps)

    # Secrets
    for name, pattern in SECRET_PATTERNS.items():
        try:
            matches = re.findall(pattern, all_js)
            if matches: results["secrets"][name] = list(set(matches[:5]))
        except: pass

    results["emails"]  = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', all_js)))[:20]
    results["phones"]  = list(set(re.findall(r'(?:\+91|0)?[6-9]\d{9}', all_js)))[:10]
    results["graphql"] = any("graphql" in ep.lower() for ep in results["endpoints"])
    return results

def domain_geo(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if r.ok:
            d = r.json()
            return {
                "ip": d.get("ip", ip), "city": d.get("city", ""),
                "region": d.get("region", ""), "country": d.get("country_name", ""),
                "org": d.get("org", ""), "asn": d.get("asn", ""),
                "timezone": d.get("timezone", ""), "latitude": d.get("latitude", ""),
                "longitude": d.get("longitude", ""),
            }
    except: pass
    return {}

def domain_port_scan(ip, ports=None):
    if ports is None: ports = list(COMMON_PORTS.keys())
    open_ports = {}
    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0: return port, COMMON_PORTS.get(port, "Unknown")
            s.close()
        except: pass
        return None, None
    with ThreadPoolExecutor(max_workers=60) as ex:
        for port, svc in ex.map(lambda p: check(p), ports):
            if port: open_ports[port] = svc
    return dict(sorted(open_ports.items()))

def detect_tech_stack(domain, headers, html):
    combined = html.lower() + " " + " ".join(f"{k}:{v}".lower() for k, v in headers.items())
    detected = []
    for tech, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined:
                detected.append(tech); break
    return sorted(set(detected))

def run_domain_intel(domain_raw, args):
    domain = re.sub(r'^https?://', '', domain_raw).strip("/").split("/")[0]
    ext    = tldextract.extract(domain)
    root   = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
    all_data = {"target": {"domain": domain, "root": root, "ts": datetime.now().isoformat()}}

    console.print(Panel(
        f"[bold white]Target:[/bold white]      [bold cyan]{domain}[/bold cyan]\n"
        f"[bold white]Root Domain:[/bold white] [cyan]{root}[/cyan]\n"
        f"[bold white]Scan Mode:[/bold white]   {'[bold red]DEEP[/bold red]' if getattr(args, 'deep', False) else '[yellow]STANDARD[/yellow]'}\n"
        f"[bold white]Started:[/bold white]     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold yellow]🎯 DOMAIN INTELLIGENCE  v3.0 — Police Edition[/bold yellow]",
        border_style="yellow", padding=(1, 2)
    ))

    # ── WHOIS ──────────────────────────────────────────────────────────────────
    section("① WHOIS Intelligence")
    with console.status("[cyan]WHOIS lookup..."):
        whois_data = domain_whois(root)
    all_data["whois"] = whois_data

    if "error" not in whois_data:
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1))
        t.add_column("Field", style="bold cyan", width=22)
        t.add_column("Value", style="white")
        for k, v in [("Registrar", whois_data.get("registrar", "")),
                     ("Org",       whois_data.get("org", "")),
                     ("Country",   whois_data.get("country", "")),
                     ("Created",   whois_data.get("creation_date", "")),
                     ("Expires",   whois_data.get("expiration_date", "")),
                     ("DNSSEC",    whois_data.get("dnssec", "")),
                     ("Name Servers", "\n".join(whois_data.get("name_servers", []))),
                     ("WHOIS Emails", "\n".join(whois_data.get("emails", []))),
        ]:
            if v and str(v) not in ("None", "[]"):
                t.add_row(k, str(v)[:120])
        console.print(t)
        age = whois_data.get("domain_age_days")
        if age is not None:
            if whois_data.get("NEW_DOMAIN_WARNING"):
                warn(f"[bold red]🚨 NEWLY REGISTERED DOMAIN — Only {age} days old — HIGH FRAUD RISK[/bold red]")
            elif whois_data.get("YOUNG_DOMAIN_WARNING"):
                warn(f"Domain is relatively young — {age} days old ({age//30} months)")
            else:
                info(f"Domain age: {age} days ({age//365} years)")

    # ── DNS ────────────────────────────────────────────────────────────────────
    section("② DNS Intelligence")
    with console.status("[cyan]DNS resolution..."):
        dns_data = domain_dns(domain)
    all_data["dns"] = dns_data

    if dns_data:
        tree = Tree(f"[bold cyan]🌐  {domain}[/bold cyan]")
        icons = {"A": "📍", "AAAA": "📍", "MX": "📧", "TXT": "📝", "NS": "🔑",
                 "CNAME": "🔗", "SOA": "📋", "CAA": "🔒", "SPF": "📮", "DMARC": "🛡", "DKIM": "🔐"}
        for rtype, records in dns_data.items():
            branch = tree.add(f"[bold yellow]{icons.get(rtype, '•')} {rtype}[/bold yellow]")
            for r in records:
                branch.add(f"[white]{r[:120]}[/white]")
        console.print(tree)
        if "DMARC" not in dns_data: warn("No DMARC record — email spoofing possible!")
        if "SPF"   not in dns_data: warn("No SPF record — email spoofing possible!")
        if "CAA"   not in dns_data: warn("No CAA record — any CA can issue certs!")

    # ── HTTP + SSL ─────────────────────────────────────────────────────────────
    section("③ HTTP / TLS Fingerprint + Security Headers")
    with console.status("[cyan]HTTP + SSL analysis..."):
        hdr_data, ssl_data = domain_headers_ssl(domain)
    all_data["http"]  = hdr_data
    all_data["ssl"]   = ssl_data

    if hdr_data:
        ht = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1))
        ht.add_column("Key", style="bold cyan", width=16)
        ht.add_column("Value")
        ht.add_row("URL",    hdr_data.get("url", ""))
        ht.add_row("Status", str(hdr_data.get("status", "")))
        ht.add_row("Server", hdr_data.get("server", "—"))
        ht.add_row("Powered", hdr_data.get("powered_by", "—"))
        console.print(ht)

        if ssl_data and "error" not in ssl_data:
            console.print("[bold yellow]🔒 TLS Certificate[/bold yellow]")
            ts = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1))
            ts.add_column("Key", style="bold cyan", width=16)
            ts.add_column("Value")
            issuer = ssl_data.get("issuer", {})
            ts.add_row("Issuer",    issuer.get("organizationName", issuer.get("commonName", "")))
            ts.add_row("Valid From", ssl_data.get("not_before", ""))
            ts.add_row("Expires",   ssl_data.get("not_after", ""))
            days = ssl_data.get("days_left", 0)
            day_s = (f"[bold red]{days} days — EXPIRED![/bold red]" if days < 0 else
                     f"[yellow]{days} days — EXPIRING SOON[/yellow]" if days < 30
                     else f"[green]{days} days[/green]")
            ts.add_row("Days Left", day_s)
            ts.add_row("SAN Count", str(ssl_data.get("san_count", 0)))
            san = ssl_data.get("san", [])
            if san: ts.add_row("SANs", ", ".join(san[:8]) + ("…" if len(san) > 8 else ""))
            if ssl_data.get("self_signed"): ts.add_row("⚠ WARNING", "[red]SELF-SIGNED CERTIFICATE![/red]")
            console.print(ts)

        sec = domain_security_headers(hdr_data.get("headers", {}))
        all_data["security_headers"] = sec
        console.print("[bold yellow]🛡 Security Headers[/bold yellow]")
        sh = Table(box=box.SIMPLE, padding=(0, 1))
        sh.add_column("Header",  style="bold", width=18)
        sh.add_column("Status",  width=18)
        for label, info_d in sec.items():
            badge = "[bold green]✓ SET[/bold green]" if info_d["present"] else f"[bold {info_d['severity']}]✗ MISSING[/bold {info_d['severity']}]"
            sh.add_row(label, badge)
        console.print(sh)

        # Tech stack detection
        html_content = hdr_data.get("html", "")
        tech = detect_tech_stack(domain, hdr_data.get("headers", {}), html_content)
        all_data["tech"] = tech
        if tech:
            section("④ Technology Stack")
            cols = [Panel(f"[bold white]{t}[/bold white]", border_style="cyan", padding=(0, 2)) for t in tech]
            console.print(Columns(cols[:12]))

    # ── IP + Geo ───────────────────────────────────────────────────────────────
    section("⑤ IP Geolocation & ASN")
    ip = resolve_ip(domain)
    all_data["ip"] = ip or ""
    if ip:
        console.print(f"  [bold yellow]IP:[/bold yellow] [bold cyan]{ip}[/bold cyan]")
        with console.status("[cyan]Geo/ASN lookup..."):
            geo = domain_geo(ip)
        all_data["geo"] = geo
        if geo:
            gt = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1))
            gt.add_column("Key", style="bold cyan", width=16)
            gt.add_column("Value", style="white")
            for k, v in geo.items():
                if v and k not in ["latitude", "longitude"]:
                    gt.add_row(k.replace("_", " ").title(), str(v))
            if geo.get("latitude") and geo.get("longitude"):
                gt.add_row("Coordinates", f"{geo['latitude']}, {geo['longitude']}")
                gt.add_row("Map Link", f"https://maps.google.com/?q={geo['latitude']},{geo['longitude']}")
            console.print(gt)

    # ── Wayback Machine ────────────────────────────────────────────────────────
    section("⑥ Wayback Machine — Archive History")
    with console.status("[cyan]Querying Internet Archive CDX API..."):
        wayback = domain_wayback(domain)
    all_data["wayback"] = wayback

    if wayback.get("snapshots", 0) > 0:
        ok(f"Archive found — {wayback['snapshots']} snapshots")
        if wayback.get("first_seen"):
            info(f"First archived: {wayback['first_seen']} → Last seen: {wayback['last_seen']}")
        console.print(f"  [yellow]📌 Archived URLs:[/yellow]")
        for url in wayback.get("urls", [])[:5]:
            console.print(f"    [cyan]{url}[/cyan]")
    else:
        info("No archive snapshots found (new or obscure domain)")

    # ── OTX Threat Intel ───────────────────────────────────────────────────────
    section("⑦ AlienVault OTX Threat Intelligence")
    with console.status("[cyan]Querying AlienVault OTX..."):
        otx = domain_otx(domain)
    all_data["otx"] = otx

    if otx.get("malicious"):
        console.print(f"  [bold red]🚨 MALICIOUS DOMAIN — {otx['pulses']} OTX threat pulse(s)![/bold red]")
        if otx.get("categories"): info(f"Categories: {', '.join(otx['categories'])}")
        if otx.get("tags"):       info(f"Tags: {', '.join(otx['tags'][:5])}")
    else:
        ok(f"OTX: No known malicious pulses found")

    if otx.get("hackertarget_hosts"):
        info(f"HackerTarget passive DNS: {len(otx['hackertarget_hosts'])} hosts")

    # ── Subdomains ─────────────────────────────────────────────────────────────
    section("⑧ Subdomain Enumeration  (crt.sh + HackerTarget + Brute Force)")
    with console.status("[cyan]Passive subdomain enumeration..."):
        passive = domain_subdomains(root)
    info(f"Passive: {len(passive)} subdomains found")

    brute = []
    if not getattr(args, "no_brute", False):
        with console.status(f"[cyan]Brute-forcing {len(COMMON_SUBDOMAINS)} subdomains..."):
            brute = domain_brute_subs(root, COMMON_SUBDOMAINS)
        info(f"Brute: {len(brute)} live subdomains confirmed")

    all_data["subdomains_passive"] = passive
    all_data["subdomains_brute"]   = [{"fqdn": f, "ip": i} for f, i in brute]

    all_subs = {s: {"ip": resolve_ip(s) or "", "source": "passive"} for s in passive}
    for fqdn, ip in brute:
        if fqdn in all_subs: all_subs[fqdn]["source"] += "+brute"
        else: all_subs[fqdn] = {"ip": ip, "source": "brute"}

    if all_subs:
        st = Table(box=box.SIMPLE, padding=(0, 1))
        st.add_column("Subdomain", style="bold white")
        st.add_column("IP",        style="cyan",   width=18)
        st.add_column("Source",    style="dim",     width=14)
        for sub, meta in sorted(all_subs.items()):
            src_s = ""
            if "passive" in meta["source"]: src_s += "[green]cert[/green] "
            if "brute"   in meta["source"]: src_s += "[yellow]brute[/yellow]"
            st.add_row(sub, meta["ip"], src_s)
        console.print(st)

    # ── Path discovery ─────────────────────────────────────────────────────────
    section("⑨ Sensitive Path & File Discovery")
    with console.status(f"[cyan]Checking {len(INTERESTING_PATHS)} paths..."):
        found_paths = domain_paths(f"https://{domain}", INTERESTING_PATHS)
    all_data["paths"] = found_paths

    if found_paths:
        pt = Table(box=box.SIMPLE, padding=(0, 1))
        pt.add_column("Status", width=8)
        pt.add_column("Size",   style="dim", width=10)
        pt.add_column("Path",   style="bold white")
        pt.add_column("Risk",   style="bold red")
        high_risk_kw = {".env", "git", "config", "backup", "sql", "dump", "swagger", "phpinfo", "admin", "debug", "actuator"}
        for item in found_paths:
            risk = "🚨 CRITICAL" if any(x in item["path"].lower() for x in high_risk_kw) else ""
            pt.add_row(status_badge(item["status"]), f"{item['size']:,}b", item["path"], risk)
        console.print(pt)
    else:
        ok("No interesting exposed paths found")

    # ── JS recon ───────────────────────────────────────────────────────────────
    section("⑩ JavaScript Reconnaissance + Secret Extraction")
    with console.status("[cyan]JS analysis in progress..."):
        js_data = domain_js_recon(f"https://{domain}")
    all_data["js"] = js_data

    info(f"Found {len(js_data['js_files'])} JS files → {len(js_data['endpoints'])} endpoints extracted")
    if js_data["graphql"]: warn("GraphQL endpoint detected!")
    if js_data.get("emails"):
        ok(f"Emails harvested from JS: {', '.join(js_data['emails'][:5])}")
    if js_data.get("phones"):
        ok(f"Phone numbers found in JS: {', '.join(js_data['phones'][:5])}")
    if js_data["secrets"]:
        console.print()
        warn("[bold red]🚨 POTENTIAL SECRETS / CREDENTIALS FOUND IN JS CODE[/bold red]")
        for stype, matches in js_data["secrets"].items():
            console.print(f"    [bold red]{stype}[/bold red] ({len(matches)} match{'es' if len(matches) > 1 else ''})")
            for m in matches[:2]:
                display = (m[:40] + "…") if len(m) > 40 else m
                console.print(f"      [red]{display}[/red]")
    else:
        ok("No obvious secrets detected in JS files")

    # ── Port scan ──────────────────────────────────────────────────────────────
    if ip and not getattr(args, "skip_ports", False):
        section("⑪ Port Scan  (Top 50 Common Ports)")
        with console.status(f"[cyan]Scanning {len(COMMON_PORTS)} ports on {ip}..."):
            open_ports = domain_port_scan(ip)
        all_data["ports"] = open_ports

        if open_ports:
            prt = Table(box=box.SIMPLE, padding=(0, 2))
            prt.add_column("Port",    style="bold yellow", width=8)
            prt.add_column("Service", style="bold white",  width=18)
            prt.add_column("Risk",    style="bold red")
            for port, svc in open_ports.items():
                risk = HIGH_RISK_PORTS.get(port, "")
                prt.add_row(str(port), svc, risk)
            console.print(prt)

    # ── Summary ────────────────────────────────────────────────────────────────
    section("📊 Scan Summary")
    summary_items = [
        ("WHOIS",          "registrar" in all_data.get("whois", {})),
        ("DNS Records",    bool(all_data.get("dns"))),
        ("SSL/TLS",        "days_left" in all_data.get("ssl", {})),
        ("Tech Stack",     len(all_data.get("tech", []))),
        ("Wayback Snaps",  all_data.get("wayback", {}).get("snapshots", 0)),
        ("OTX Pulses",     all_data.get("otx", {}).get("pulses", 0)),
        ("Subdomains",     len(all_data.get("subdomains_passive", []))),
        ("Brute Subs",     len(all_data.get("subdomains_brute", []))),
        ("Exposed Paths",  len(all_data.get("paths", []))),
        ("JS Endpoints",   len(all_data.get("js", {}).get("endpoints", []))),
        ("JS Secrets",     len(all_data.get("js", {}).get("secrets", {}))),
        ("Harvested Emails", len(all_data.get("js", {}).get("emails", []))),
        ("Open Ports",     len(all_data.get("ports", {}))),
    ]
    st = Table(box=box.DOUBLE_EDGE, padding=(0, 2), title="[bold yellow]Results[/bold yellow]")
    st.add_column("Module",  style="bold white", width=22)
    st.add_column("Result",  justify="right")
    for name, val in summary_items:
        if isinstance(val, bool):
            st.add_row(name, "[bold green]✓[/bold green]" if val else "[dim]—[/dim]")
        else:
            color = "bold green" if val > 0 else "dim"
            st.add_row(name, f"[{color}]{val}[/{color}]")
    console.print(st)

    return all_data


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5: CROSS-PIVOT INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def run_cross_pivot(all_data):
    """Auto-pivot between intelligence artifacts to find connections"""
    section("🔗 CROSS-PIVOT INTELLIGENCE ENGINE")
    pivots = []
    findings = []

    # Phone → Find linked email patterns
    phone_core = all_data.get("phone_intel", {}).get("core", {})
    if phone_core.get("valid"):
        nat = phone_core.get("national", "").replace(" ", "").replace("-", "")
        e164 = phone_core.get("e164", "").replace("+", "")
        console.print(f"\n[bold yellow]📞 → 📧  Phone-to-Email Pivot[/bold yellow]")
        email_guesses = [
            f"{nat}@gmail.com", f"{nat}@yahoo.com", f"{nat}@outlook.com",
            f"{e164}@gmail.com",
        ]
        for eg in email_guesses:
            console.print(f"  [dim]Check: {eg}[/dim]")
        pivots.append({"type": "phone→email", "queries": email_guesses})

        # Phone → Domain hints
        console.print(f"\n[bold yellow]📞 → 🌐  Phone-to-Domain Pivot[/bold yellow]")
        g = lambda q: f"https://www.google.com/search?q={urllib.parse.quote(q)}"
        domain_dorks = [
            g(f'"{nat}" inurl:contact OR inurl:about'),
            g(f'"{nat}" "registered domain"'),
            g(f'"{e164}" site:linkedin.com/company'),
        ]
        for d in domain_dorks:
            console.print(f"  [cyan]{d[:100]}[/cyan]")
        pivots.append({"type": "phone→domain", "dorks": domain_dorks})

    # Email → Username pivot
    email_data = all_data.get("email_intel", {})
    if email_data.get("username"):
        uname = email_data["username"]
        console.print(f"\n[bold yellow]📧 → 👤  Email-to-Username Pivot[/bold yellow]")
        console.print(f"  [bold cyan]Extracted username: @{uname}[/bold cyan]")
        console.print(f"  [dim]Run: python osint_pro.py --username {uname}[/dim]")
        # GitHub already checked, check others quickly
        quick_hits = []
        for platform, url_tpl in [("Telegram", "https://t.me/{}"), ("Twitter/X", "https://x.com/{}"),
                                    ("GitHub", "https://github.com/{}")]:
            url = url_tpl.format(uname)
            r = safe_get(url, timeout=6)
            if r and r.status_code not in [404, 410]:
                quick_hits.append((platform, url))
                console.print(f"  [green]✓ @{uname} exists on {platform}[/green]  → [cyan]{url}[/cyan]")
        pivots.append({"type": "email→username", "username": uname, "quick_hits": quick_hits})

    # Domain → Email harvest
    domain_data = all_data.get("domain_intel", {})
    if domain_data:
        emails = domain_data.get("js", {}).get("emails", [])
        whois_emails = domain_data.get("whois", {}).get("emails", [])
        all_emails = list(set(emails + whois_emails))
        if all_emails:
            console.print(f"\n[bold yellow]🌐 → 📧  Domain-to-Email Harvest[/bold yellow]")
            for email in all_emails[:8]:
                console.print(f"  [green]✓ Harvested:[/green] [cyan]{email}[/cyan]")
            pivots.append({"type": "domain→email", "emails": all_emails})

        # Domain → Username hints
        domain_name = domain_data.get("target", {}).get("domain", "")
        if domain_name:
            uname_guess = domain_name.split(".")[0]
            console.print(f"\n[bold yellow]🌐 → 👤  Domain-to-Username Pivot[/bold yellow]")
            console.print(f"  [dim]Username guess: @{uname_guess}[/dim]")
            console.print(f"  [dim]Run: python osint_pro.py --username {uname_guess}[/dim]")
            pivots.append({"type": "domain→username", "guess": uname_guess})

    # Username → Phone hint
    username_data = all_data.get("username_intel", {})
    if username_data.get("found"):
        console.print(f"\n[bold yellow]👤 → 📱  Username-to-Phone Pivot[/bold yellow]")
        found_platforms = [f["site"] for f in username_data["found"]]
        console.print(f"  Profile found on: {', '.join(found_platforms[:5])}")
        console.print(f"  [dim]→ Check each profile for linked phone / contact info[/dim]")
        console.print(f"  [dim]→ Instagram/Facebook profiles sometimes show phone if linked[/dim]")
        pivots.append({"type": "username→phone", "platforms": found_platforms})

    # Timeline construction
    console.print(f"\n[bold yellow]⏱  Evidence Timeline[/bold yellow]")
    timeline = []

    # Domain creation date
    whois_d = domain_data.get("whois", {}) if domain_data else {}
    if whois_d.get("creation_date"):
        timeline.append({"date": str(whois_d["creation_date"])[:10], "event": "Domain registered",
                         "source": "WHOIS"})

    # First wayback snapshot
    wayback_d = domain_data.get("wayback", {}) if domain_data else {}
    if wayback_d.get("first_seen"):
        fs = wayback_d["first_seen"]
        timeline.append({"date": f"{fs[:4]}-{fs[4:6]}-{fs[6:]}", "event": "First web archive snapshot",
                         "source": "Wayback Machine"})

    # GitHub commits
    if email_data.get("github", {}).get("commits", 0) > 0:
        for repo in email_data.get("github", {}).get("repos", [])[:2]:
            timeline.append({"date": "?", "event": f"GitHub commit in {repo['repo']}: {repo['msg'][:40]}",
                             "source": "GitHub"})

    if timeline:
        tl = Table(box=box.SIMPLE, padding=(0, 1))
        tl.add_column("Date",   style="bold cyan", width=14)
        tl.add_column("Event",  style="white")
        tl.add_column("Source", style="dim",       width=18)
        for item in sorted(timeline, key=lambda x: x["date"]):
            tl.add_row(item["date"], item["event"], item["source"])
        console.print(tl)

    all_data["cross_pivot"] = {"pivots": pivots, "timeline": timeline}
    return all_data


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6: AI NARRATIVE REPORT (Claude API)
# ══════════════════════════════════════════════════════════════════════════════
def generate_ai_narrative(all_data, target_label):
    """Generate police-grade intelligence narrative using Claude AI"""
    if not HAS_ANTHROPIC:
        warn("anthropic library not installed — skipping AI narrative")
        warn("Install: pip install anthropic")
        return ""

    section("🤖 AI INTELLIGENCE NARRATIVE  (Claude AI — Police Report Generator)")

    # Build intelligence summary for Claude
    summary_lines = [f"OSINT Intelligence Report — Target: {target_label}", ""]

    phone_core = all_data.get("phone_intel", {}).get("core", {})
    if phone_core.get("valid"):
        summary_lines += [
            "=== PHONE INTELLIGENCE ===",
            f"Number: {phone_core.get('e164', '')}  Region: {phone_core.get('region', '')}",
            f"Carrier: {phone_core.get('carrier', '')}  Line Type: {phone_core.get('line_type', '')}",
            f"Location: {phone_core.get('geo', '')}",
        ]
        risk = all_data.get("phone_intel", {}).get("risk", {})
        if risk: summary_lines.append(f"Risk Score: {risk.get('score', 0)}/100 — {risk.get('level', '')}")
        cdb = all_data.get("phone_intel", {}).get("carrier_db", {})
        if cdb.get("ported_hint"): summary_lines.append("SIM PORTING: Detected — possible MNP fraud")
        social = all_data.get("phone_intel", {}).get("social", [])
        for s in social:
            if s.get("found"): summary_lines.append(f"{s['platform']}: REGISTERED")
        spam_hits = sum(r.get("reports", 0) for r in all_data.get("phone_intel", {}).get("spam_checks", []) if isinstance(r, dict))
        if spam_hits > 0: summary_lines.append(f"Spam Reports: {spam_hits} across public databases")
        summary_lines.append("")

    email_d = all_data.get("email_intel", {})
    if email_d.get("input"):
        summary_lines += [
            "=== EMAIL INTELLIGENCE ===",
            f"Email: {email_d.get('input', '')}",
            f"Disposable: {'YES — HIGH RISK' if email_d.get('disposable') else 'No'}",
            f"Provider: {'Free/Public' if email_d.get('free_provider') else 'Corporate/Custom'}",
        ]
        smtp = email_d.get("smtp_probe", {})
        if smtp.get("exists") is True: summary_lines.append("SMTP Verification: MAILBOX CONFIRMED EXISTS")
        elif smtp.get("exists") is False: summary_lines.append("SMTP Verification: MAILBOX DOES NOT EXIST")
        breaches = email_d.get("breaches", [])
        if breaches: summary_lines.append(f"BREACHES: Found in {len(breaches)} breach database(s)")
        github = email_d.get("github", {})
        if github.get("commits", 0) > 0:
            summary_lines.append(f"GitHub: {github['commits']} commits — username: @{github.get('username', '')}")
        summary_lines.append("")

    username_d = all_data.get("username_intel", {})
    if username_d.get("username"):
        found_sites = [f["site"] for f in username_d.get("found", [])]
        summary_lines += [
            "=== USERNAME INTELLIGENCE ===",
            f"Username: @{username_d['username']}",
            f"Found on {len(found_sites)} platforms: {', '.join(found_sites[:10])}",
            "",
        ]

    domain_d = all_data.get("domain_intel", {})
    if domain_d.get("target"):
        whois_d = domain_d.get("whois", {})
        summary_lines += [
            "=== DOMAIN INTELLIGENCE ===",
            f"Domain: {domain_d['target'].get('domain', '')}",
            f"Registrar: {whois_d.get('registrar', 'Unknown')}",
            f"Age: {whois_d.get('domain_age_days', '?')} days",
            f"NEW DOMAIN WARNING: {'YES' if whois_d.get('NEW_DOMAIN_WARNING') else 'No'}",
        ]
        otx = domain_d.get("otx", {})
        if otx.get("malicious"): summary_lines.append(f"OTX THREAT: MALICIOUS — {otx['pulses']} pulses!")
        ports = domain_d.get("ports", {})
        high_risk = [p for p in ports if p in HIGH_RISK_PORTS]
        if high_risk: summary_lines.append(f"CRITICAL OPEN PORTS: {high_risk}")
        js_secrets = domain_d.get("js", {}).get("secrets", {})
        if js_secrets: summary_lines.append(f"EXPOSED SECRETS IN CODE: {list(js_secrets.keys())}")
        summary_lines.append("")

    pivots = all_data.get("cross_pivot", {}).get("pivots", [])
    if pivots:
        summary_lines += ["=== CROSS-PIVOT CONNECTIONS ==="]
        for p in pivots:
            summary_lines.append(f"{p['type']}: {str(p)[:100]}")

    intel_summary = "\n".join(summary_lines)

    prompt = f"""You are a senior cybercrime intelligence analyst working for law enforcement. 
Based on the following OSINT intelligence findings, write a professional police-grade intelligence report.

Your report must include:
1. **EXECUTIVE SUMMARY** — 3-4 sentences on what this investigation found
2. **SUBJECT PROFILE** — What is known about the target
3. **THREAT ASSESSMENT** — Is this a fraudster, scammer, cybercriminal? Risk level?
4. **KEY INDICATORS OF COMPROMISE (IOCs)** — Specific red flags found
5. **DIGITAL FOOTPRINT** — Where the subject exists online
6. **RECOMMENDED INVESTIGATIVE ACTIONS** — 5 specific next steps for police
7. **LEGAL ACTION POTENTIAL** — What charges/sections could apply (include IPC/IT Act for India if relevant)

Write in formal law enforcement language. Be specific and actionable. Highlight the most critical findings.

INTELLIGENCE FINDINGS:
{intel_summary}

Write the report now:"""

    try:
        with console.status("[cyan]🤖 Claude AI generating intelligence narrative..."):
            client = anthropic.Anthropic()
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            narrative = message.content[0].text

        console.print()
        console.print(Panel(
            narrative,
            title="[bold yellow]🤖 AI Intelligence Narrative — Claude[/bold yellow]",
            border_style="cyan", padding=(1, 2)
        ))
        return narrative

    except Exception as e:
        err(f"AI narrative failed: {e}")
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 7: HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
def generate_html_report(all_data, target_label, narrative=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def card(title, content, color="cyan"):
        return f"""
        <div class="card">
            <div class="card-header" style="border-left:4px solid var(--{color})">
                <h3>{esc(title)}</h3>
            </div>
            <div class="card-body">{content}</div>
        </div>"""

    def kv(k, v, highlight=False):
        style = ' style="color:var(--red);font-weight:bold"' if highlight else ""
        return f'<tr><td class="key">{esc(k)}</td><td{style}>{esc(str(v))}</td></tr>'

    def table(rows, headers=None):
        h = ""
        if headers:
            h = "<thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr></thead>"
        body = "<tbody>" + "".join("<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in row) + "</tr>" for row in rows) + "</tbody>"
        return f"<table>{h}{body}</table>"

    # Build content sections
    sections_html = []

    # Phone
    phone_d = all_data.get("phone_intel", {})
    phone_core = phone_d.get("core", {})
    if phone_core.get("valid"):
        risk = phone_d.get("risk", {})
        score = risk.get("score", 0)
        risk_color = "red" if score >= 50 else "yellow" if score >= 25 else "green"
        rows = [
            ("E.164",          phone_core.get("e164", "")),
            ("International",  phone_core.get("international", "")),
            ("National",       phone_core.get("national", "")),
            ("Region",         f"{phone_core.get('region','')} (+{phone_core.get('country_code','')})"),
            ("Carrier",        phone_core.get("carrier", "")),
            ("Location",       phone_core.get("geo", "")),
            ("Line Type",      f"{phone_core.get('line_type','')} {phone_core.get('line_icon','')}"),
            ("Timezones",      ", ".join(phone_core.get("timezones", []))),
        ]
        cdb = phone_d.get("carrier_db", {})
        if cdb.get("carrier"):
            rows += [("DB Carrier", cdb["carrier"]), ("Circle", cdb.get("circle", "")),
                     ("Network", cdb.get("type", ""))]
        if cdb.get("ported_hint"):
            rows.append(("⚠ SIM PORTING", cdb.get("ported_note", "DETECTED")))

        content = f'<table class="kv-table">{"".join(kv(k, v, "WARNING" in str(v) or "PORTED" in str(k)) for k, v in rows)}</table>'
        content += f'<div class="risk-bar"><div class="risk-label">Fraud Risk Score: <strong style="color:var(--{risk_color})">{score}/100 — {esc(risk.get("level",""))}</strong></div>'
        content += f'<div class="progress"><div class="progress-fill" style="width:{score}%;background:var(--{risk_color})"></div></div></div>'
        if risk.get("reasons"):
            content += "<div class='evidence'><h4>Evidence Chain:</h4><ul>" + "".join(f"<li>{esc(r)}</li>" for r in risk["reasons"]) + "</ul></div>"
        sections_html.append(card("📞 Phone Intelligence", content, "yellow"))

        # Social
        social = phone_d.get("social", [])
        if social:
            rows2 = [(s.get("platform",""), s.get("status","").replace("[bold green]","").replace("[/bold green]","").replace("[red]","").replace("[/red]","").replace("[dim]","").replace("[/dim]",""), s.get("url","")) for s in social]
            content2 = table(rows2, ["Platform", "Status", "URL"])
            sections_html.append(card("📱 Social & Messaging Presence", content2, "cyan"))

        # Spam
        spam = phone_d.get("spam_checks", [])
        if spam:
            rows3 = [(r.get("source",""), r.get("reports","0"), r.get("name","") or r.get("rating","") or r.get("status",""), ", ".join(r.get("fraud_keywords",[])[:3])) for r in spam if isinstance(r, dict)]
            content3 = table(rows3, ["Database", "Reports", "Name/Status", "Fraud Keywords"])
            sections_html.append(card("🚨 Spam & Fraud Databases", content3, "red"))

    # Email
    email_d = all_data.get("email_intel", {})
    if email_d.get("input"):
        rows = [
            ("Email",        email_d.get("input","")),
            ("Username",     email_d.get("username","")),
            ("Domain",       email_d.get("domain","")),
            ("Disposable?",  "⚠ YES — TEMP MAIL" if email_d.get("disposable") else "No"),
            ("Provider",     "Free/Public" if email_d.get("free_provider") else "Corporate"),
        ]
        smtp = email_d.get("smtp_probe", {})
        if smtp.get("exists") is True:   rows.append(("SMTP Verify", "✓ MAILBOX EXISTS"))
        elif smtp.get("exists") is False: rows.append(("SMTP Verify", "✗ MAILBOX DOES NOT EXIST"))
        else: rows.append(("SMTP Verify", smtp.get("detail","Inconclusive")))

        grav = email_d.get("gravatar", {})
        if grav.get("found"): rows.append(("Gravatar", f"PHOTO FOUND — {grav.get('url','')}"))

        github = email_d.get("github", {})
        if github.get("commits", 0) > 0:
            rows.append(("GitHub Commits", f"{github['commits']} commits — @{github.get('username','')}"))

        breaches = email_d.get("breaches", [])
        if breaches: rows.append(("🚨 Breaches", f"Found in {len(breaches)} breach source(s)!"))

        content = f'<table class="kv-table">{"".join(kv(k, v, "YES" in str(v) and k in ["Disposable?","🚨 Breaches"]) for k, v in rows)}</table>'
        sections_html.append(card("📧 Email Intelligence", content, "yellow"))

    # Username
    username_d = all_data.get("username_intel", {})
    if username_d.get("found"):
        rows = [(f["site"], f["url"], str(f.get("status",""))) for f in username_d["found"]]
        content = f'<p>Found <strong>{len(rows)}</strong> profiles for <strong>@{esc(username_d.get("username",""))}</strong></p>'
        content += table(rows, ["Platform", "URL", "HTTP Status"])
        sections_html.append(card("👤 Username Hunt", content, "green"))

    # Domain
    domain_d = all_data.get("domain_intel", {})
    if domain_d.get("target"):
        whois_d = domain_d.get("whois", {})
        geo = domain_d.get("geo", {})
        age = whois_d.get("domain_age_days", "?")
        rows = [
            ("Domain",     domain_d["target"].get("domain","")),
            ("IP Address", domain_d.get("ip","")),
            ("Registrar",  whois_d.get("registrar","")),
            ("Country",    whois_d.get("country","")),
            ("Created",    whois_d.get("creation_date","")),
            ("Expires",    whois_d.get("expiration_date","")),
            ("Domain Age", f"{age} days"),
            ("City",       f"{geo.get('city','')}, {geo.get('country','')}"),
            ("ASN/Org",    f"{geo.get('asn','')} {geo.get('org','')}"),
        ]
        if whois_d.get("NEW_DOMAIN_WARNING"):
            rows.append(("⚠ WARNING", "NEWLY REGISTERED DOMAIN — HIGH FRAUD RISK!"))

        content = f'<table class="kv-table">{"".join(kv(k, v, "WARNING" in k) for k, v in rows)}</table>'

        # OTX
        otx = domain_d.get("otx", {})
        if otx.get("malicious"):
            content += f'<div class="alert alert-danger">🚨 OTX THREAT INTEL: MALICIOUS — {otx["pulses"]} threat pulse(s)!</div>'
        else:
            content += '<div class="alert alert-success">✓ OTX: No known malicious activity</div>'

        # Wayback
        wb = domain_d.get("wayback", {})
        if wb.get("snapshots", 0) > 0:
            content += f'<div class="alert alert-info">📚 Wayback: {wb["snapshots"]} snapshots — First seen: {wb.get("first_seen","?")} Last: {wb.get("last_seen","?")}</div>'

        sections_html.append(card("🌐 Domain Intelligence", content, "cyan"))

        # Subdomains
        subs_passive = domain_d.get("subdomains_passive", [])
        subs_brute   = domain_d.get("subdomains_brute", [])
        if subs_passive or subs_brute:
            rows2 = [(s, "", "cert") for s in subs_passive[:30]] + [(d["fqdn"], d.get("ip",""), "brute") for d in subs_brute[:20]]
            content2 = f'<p>Found <strong>{len(subs_passive)}</strong> passive + <strong>{len(subs_brute)}</strong> brute-force subdomains</p>'
            content2 += table(rows2[:40], ["Subdomain", "IP", "Source"])
            sections_html.append(card("🔍 Subdomain Enumeration", content2))

        # Exposed paths
        paths = domain_d.get("paths", [])
        if paths:
            rows3 = [(str(p["status"]), p["path"], f"{p['size']:,} bytes") for p in paths]
            content3 = f'<p>Found <strong>{len(paths)}</strong> interesting path(s)</p>'
            content3 += table(rows3, ["Status", "Path", "Size"])
            sections_html.append(card("🚨 Exposed Paths & Files", content3, "red"))

        # JS Secrets
        js = domain_d.get("js", {})
        secrets = js.get("secrets", {})
        if secrets:
            rows4 = [(stype, len(matches), (matches[0][:40] + "…") if matches else "") for stype, matches in secrets.items()]
            content4 = '<div class="alert alert-danger">🚨 CREDENTIALS/SECRETS FOUND IN JAVASCRIPT</div>'
            content4 += table(rows4, ["Secret Type", "Matches", "Sample"])
            sections_html.append(card("🔑 Exposed Secrets in JS", content4, "red"))

        # Open ports
        open_ports = domain_d.get("ports", {})
        if open_ports:
            rows5 = [(str(p), svc, HIGH_RISK_PORTS.get(p, "")) for p, svc in open_ports.items()]
            content5 = table(rows5, ["Port", "Service", "Risk"])
            sections_html.append(card("🔌 Open Ports", content5, "red"))

    # AI Narrative section
    if narrative:
        nar_html = "<div class='narrative'>" + narrative.replace("\n", "<br>").replace("**", "<strong>").replace("**", "</strong>") + "</div>"
        sections_html.append(card("🤖 AI Intelligence Narrative", nar_html, "purple"))

    # Build final HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT PRO v3.0 — Police Intelligence Report: {esc(target_label)}</title>
<style>
  :root {{
    --bg: #0a0e1a; --surface: #111827; --surface2: #1e2a3a;
    --cyan: #00d4ff; --yellow: #ffd700; --green: #00ff88;
    --red: #ff4757; --orange: #ff6b35; --purple: #bf5af2;
    --text: #e2e8f0; --muted: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Consolas','Monaco',monospace; font-size:13px; }}
  .header {{
    background: linear-gradient(135deg,#0a0e1a 0%,#1a1040 50%,#0a1628 100%);
    border-bottom: 2px solid var(--cyan); padding: 30px 40px;
    display: flex; justify-content: space-between; align-items: center;
  }}
  .header h1 {{ color: var(--cyan); font-size: 1.8em; letter-spacing: 0.1em; }}
  .header .meta {{ color: var(--muted); font-size:0.9em; line-height:1.8; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:20px;
            background:var(--yellow); color:#000; font-weight:bold; font-size:0.8em; }}
  .container {{ max-width:1400px; margin:0 auto; padding:30px 20px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(600px,1fr)); gap:20px; }}
  .card {{ background:var(--surface); border-radius:10px; overflow:hidden;
           border: 1px solid rgba(255,255,255,0.05); box-shadow:0 4px 20px rgba(0,0,0,0.4); }}
  .card-header {{ padding:14px 20px; background:rgba(0,0,0,0.3); }}
  .card-header h3 {{ font-size:1em; letter-spacing:0.05em; color:var(--text); }}
  .card-body {{ padding:20px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:rgba(0,0,0,0.4); color:var(--cyan); padding:8px 12px;
        text-align:left; font-size:0.85em; letter-spacing:0.05em; }}
  td {{ padding:7px 12px; border-bottom:1px solid rgba(255,255,255,0.04);
        font-size:0.9em; vertical-align:top; }}
  tr:hover td {{ background:rgba(255,255,255,0.03); }}
  .kv-table .key {{ color:var(--muted); width:35%; font-size:0.85em; }}
  .risk-bar {{ margin-top:15px; }}
  .risk-label {{ margin-bottom:6px; font-size:0.9em; }}
  .progress {{ background:rgba(255,255,255,0.1); border-radius:4px; height:8px; }}
  .progress-fill {{ height:100%; border-radius:4px; transition:width 1s; }}
  .evidence {{ margin-top:12px; padding:12px; background:rgba(0,0,0,0.3); border-radius:6px; }}
  .evidence h4 {{ color:var(--yellow); font-size:0.85em; margin-bottom:8px; }}
  .evidence ul {{ list-style:none; }}
  .evidence li {{ color:var(--muted); font-size:0.85em; padding:2px 0; }}
  .alert {{ padding:10px 14px; border-radius:6px; margin:10px 0; font-size:0.9em; }}
  .alert-danger  {{ background:rgba(255,71,87,0.15); border:1px solid var(--red); color:var(--red); }}
  .alert-success {{ background:rgba(0,255,136,0.1); border:1px solid var(--green); color:var(--green); }}
  .alert-info    {{ background:rgba(0,212,255,0.1); border:1px solid var(--cyan); color:var(--cyan); }}
  .narrative {{ white-space:pre-wrap; line-height:1.7; font-size:0.9em; color:var(--text); }}
  .footer {{ text-align:center; padding:30px; color:var(--muted); font-size:0.8em;
             border-top:1px solid rgba(255,255,255,0.05); margin-top:20px; }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:15px; margin-bottom:25px; }}
  .stat {{ background:var(--surface); border-radius:8px; padding:15px; text-align:center;
           border:1px solid rgba(255,255,255,0.05); }}
  .stat .num {{ font-size:2em; font-weight:bold; color:var(--cyan); }}
  .stat .lbl {{ color:var(--muted); font-size:0.8em; margin-top:4px; }}
  a {{ color:var(--cyan); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  strong {{ color:var(--yellow); }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>🔍 OSINT PRO v3.0</h1>
    <div style="color:var(--yellow);margin-top:5px;font-size:1.1em">Police Intelligence Report</div>
    <div style="color:var(--muted);margin-top:5px">Target: <strong style="color:var(--cyan)">{esc(target_label)}</strong></div>
  </div>
  <div class="meta">
    <div>Generated: {ts}</div>
    <div>Classification: <span class="badge">LAW ENFORCEMENT USE</span></div>
    <div style="margin-top:5px">SpiderFoot-class · Sherlock-class · AI-Enhanced</div>
  </div>
</div>

<div class="container">
"""

    # Quick stats
    stats = []
    if phone_core.get("valid"):
        risk = all_data.get("phone_intel", {}).get("risk", {})
        stats.append((str(risk.get("score", 0)) + "/100", "Risk Score"))
        stats.append((str(sum(r.get("reports", 0) for r in all_data.get("phone_intel", {}).get("spam_checks", []) if isinstance(r, dict))), "Spam Reports"))
    if username_d.get("found"):
        stats.append((str(len(username_d["found"])), "Profiles Found"))
    if domain_d.get("target"):
        stats.append((str(len(domain_d.get("subdomains_passive", []))), "Subdomains"))
        stats.append((str(len(domain_d.get("paths", []))), "Exposed Paths"))
        stats.append((str(len(domain_d.get("js", {}).get("secrets", {}))), "JS Secrets"))

    if stats:
        html += '<div class="stat-grid">'
        for num, lbl in stats:
            html += f'<div class="stat"><div class="num">{esc(num)}</div><div class="lbl">{esc(lbl)}</div></div>'
        html += '</div>'

    html += '<div class="grid">'
    html += "".join(sections_html)
    html += '</div>'

    html += f"""
</div>
<div class="footer">
  <p>OSINT PRO v3.0 — Police Intelligence Edition | Generated {ts}</p>
  <p style="margin-top:5px">For Law Enforcement Use | All data sourced from public domain information</p>
</div>
</body>
</html>"""

    return html


# ══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_all(target_label, all_data, ai_narrative=""):
    slug = safe_slug(target_label)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out  = Path(f"osint_pro_{slug}_{ts}")
    out.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = out / "full_report.json"
    with open(json_path, "w") as f:
        json.dump(all_data, f, indent=2, default=str)
    ok(f"JSON   → {json_path}")

    # HTML Report
    html_path = out / "report.html"
    html = generate_html_report(all_data, target_label, ai_narrative)
    with open(html_path, "w") as f:
        f.write(html)
    ok(f"HTML   → {html_path}  [bold green](Open in browser for full visual report)[/bold green]")

    # AI Narrative TXT
    if ai_narrative:
        nar_path = out / "ai_narrative.txt"
        with open(nar_path, "w") as f:
            f.write(ai_narrative)
        ok(f"AI TXT → {nar_path}")

    # Dorks TXT
    dorks_data = {}
    for key in ["phone_intel", "email_intel", "username_intel"]:
        d = all_data.get(key, {}).get("dorks", {})
        if d: dorks_data.update(d)
    if dorks_data:
        dork_path = out / "investigation_dorks.txt"
        with open(dork_path, "w") as f:
            f.write(f"OSINT PRO v3.0 — Investigation Links\nTarget: {target_label}\n\n")
            if isinstance(dorks_data, dict):
                for cat, items in dorks_data.items():
                    f.write(f"\n=== {cat} ===\n")
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, (list, tuple)) and len(item) == 2:
                                f.write(f"{item[0]}\n{item[1]}\n\n")
            elif isinstance(dorks_data, list):
                for item in dorks_data:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        f.write(f"{item[0]}\n{item[1]}\n\n")
        ok(f"Dorks  → {dork_path}")

    console.print(f"\n[bold green]📁 Report saved to: [cyan]{out}/[/cyan][/bold green]")
    console.print(f"[bold yellow]   → Open [cyan]report.html[/cyan] in your browser for the full visual intelligence report[/bold yellow]")
    return str(out)


# ══════════════════════════════════════════════════════════════════════════════
# CLI MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="OSINT PRO v3.0 — Police Intelligence Edition",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python osint_pro.py example.com                    # Full domain recon
  python osint_pro.py --phone +919876543210           # Deep phone intelligence
  python osint_pro.py --email suspect@gmail.com       # Email investigation
  python osint_pro.py --username johndoe              # Username hunt 200+ sites
  python osint_pro.py --phone +91XXXXXXXXXX --pivot   # Auto cross-pivot intelligence
  python osint_pro.py --phone +91XXX --ai-report      # + AI narrative + HTML report
  python osint_pro.py example.com --deep              # Deep scan + brute force
  python osint_pro.py --phone +91XXX --email x@y.com  # Multi-target (all at once)
"""
    )
    parser.add_argument("target",         nargs="?",    help="Target domain")
    parser.add_argument("--phone",                      help="Phone number e.g. +919876543210")
    parser.add_argument("--email",                      help="Email address to investigate")
    parser.add_argument("--username",                   help="Username to hunt across 200+ sites")
    parser.add_argument("--region",       default="IN", help="Default region for phone (default: IN)")
    parser.add_argument("--pivot",        action="store_true", help="Auto cross-pivot between intelligence")
    parser.add_argument("--ai-report",    action="store_true", help="Generate AI narrative (requires anthropic)")
    parser.add_argument("--deep",         action="store_true", help="Deep scan mode")
    parser.add_argument("--no-brute",     action="store_true", help="Skip subdomain brute-force")
    parser.add_argument("--skip-ports",   action="store_true", help="Skip port scan")
    parser.add_argument("--no-export",    action="store_true", help="Don't save to disk")
    args = parser.parse_args()

    if not any([args.phone, args.email, args.username, args.target]):
        console.print(BANNER)
        parser.print_help()
        return

    console.print(BANNER)
    all_data = {}

    # ── Phone ──────────────────────────────────────────────────────────────────
    if args.phone:
        phone_data = run_phone_intel(args.phone, region=args.region.upper())
        all_data["phone_intel"] = phone_data

    # ── Email ──────────────────────────────────────────────────────────────────
    if args.email:
        email_data = run_email_intel(args.email)
        all_data["email_intel"] = email_data

    # ── Username ───────────────────────────────────────────────────────────────
    if args.username:
        uname_data = run_username_hunt(args.username)
        all_data["username_intel"] = uname_data

    # ── Domain ─────────────────────────────────────────────────────────────────
    if args.target:
        domain_data = run_domain_intel(args.target, args)
        all_data["domain_intel"] = domain_data

    # ── Cross-pivot ────────────────────────────────────────────────────────────
    if args.pivot:
        all_data = run_cross_pivot(all_data)

    # ── AI Narrative ───────────────────────────────────────────────────────────
    ai_narrative = ""
    if args.ai_report:
        target_label = args.phone or args.email or args.username or args.target or "unknown"
        ai_narrative = generate_ai_narrative(all_data, target_label)
        all_data["ai_narrative"] = ai_narrative

    # ── Export ─────────────────────────────────────────────────────────────────
    if not args.no_export:
        section("💾 Exporting Intelligence Report")
        target_label = args.phone or args.email or args.username or args.target or "osint_target"
        export_all(target_label, all_data, ai_narrative)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚡ Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
        raise
