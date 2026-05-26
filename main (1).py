"""
OSINT PRO v3.0 — FastAPI Backend
Police Intelligence Platform
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn, json, re, time
from datetime import datetime

# Import your OSINT engine
from osint_engine import (
    phone_run, email_run, username_run, domain_run,
    pivot_run, fir_run
)

# ─── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="OSINT PRO v3.0 — Police Intelligence API",
    description="Cyber Fraud Investigation Platform for Law Enforcement",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Frontend can be anywhere in Codespaces
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request Models ───────────────────────────────────────────────────────────
class PhoneRequest(BaseModel):
    number: str
    region: Optional[str] = "IN"

class EmailRequest(BaseModel):
    email: str

class UsernameRequest(BaseModel):
    username: str

class DomainRequest(BaseModel):
    domain: str
    deep: Optional[bool] = False
    skip_ports: Optional[bool] = False

class PivotRequest(BaseModel):
    phone:    Optional[str] = None
    email:    Optional[str] = None
    username: Optional[str] = None
    domain:   Optional[str] = None

class FIRRequest(BaseModel):
    target:     str
    intel_data: dict             # Full OSINT data from previous calls
    incident_type: Optional[str] = "Cyber Fraud"
    complainant:   Optional[str] = ""
    station:       Optional[str] = ""

# ─── Helper ───────────────────────────────────────────────────────────────────
def ok(data: dict, meta: dict = {}):
    return {"status": "success", "ts": datetime.now().isoformat(), "data": data, **meta}

def fail(msg: str, code: int = 400):
    return JSONResponse(status_code=code,
                        content={"status": "error", "message": msg,
                                 "ts": datetime.now().isoformat()})

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "tool":    "OSINT PRO v3.0 — Police Intelligence Platform",
        "status":  "operational",
        "endpoints": ["/api/phone", "/api/email", "/api/username",
                      "/api/domain", "/api/pivot", "/api/fir", "/api/health"],
        "docs":    "/docs"
    }

@app.get("/api/health")
def health():
    return {"status": "healthy", "version": "3.0.0",
            "ts": datetime.now().isoformat()}

# ── Phone ─────────────────────────────────────────────────────────────────────
@app.post("/api/phone")
def analyze_phone(req: PhoneRequest):
    if not req.number or len(req.number.strip()) < 7:
        return fail("Invalid phone number")
    try:
        t0 = time.time()
        result = phone_run(req.number.strip(), req.region.upper())
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed, "target": req.number})
    except Exception as e:
        return fail(str(e), 500)

# ── Email ─────────────────────────────────────────────────────────────────────
@app.post("/api/email")
def analyze_email(req: EmailRequest):
    email = req.email.strip().lower()
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return fail("Invalid email format")
    try:
        t0 = time.time()
        result = email_run(email)
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed, "target": email})
    except Exception as e:
        return fail(str(e), 500)

# ── Username ──────────────────────────────────────────────────────────────────
@app.post("/api/username")
def analyze_username(req: UsernameRequest):
    username = req.username.strip().lstrip("@")
    if not username or len(username) < 2:
        return fail("Invalid username")
    try:
        t0 = time.time()
        result = username_run(username)
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed, "target": username})
    except Exception as e:
        return fail(str(e), 500)

# ── Domain ────────────────────────────────────────────────────────────────────
@app.post("/api/domain")
def analyze_domain(req: DomainRequest):
    domain = req.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).strip("/").split("/")[0]
    if not domain or "." not in domain:
        return fail("Invalid domain")
    try:
        t0 = time.time()
        result = domain_run(domain, deep=req.deep, skip_ports=req.skip_ports)
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed, "target": domain})
    except Exception as e:
        return fail(str(e), 500)

# ── Cross-Pivot ───────────────────────────────────────────────────────────────
@app.post("/api/pivot")
def cross_pivot(req: PivotRequest):
    if not any([req.phone, req.email, req.username, req.domain]):
        return fail("Provide at least one target: phone, email, username, or domain")
    try:
        t0 = time.time()
        result = pivot_run(
            phone=req.phone, email=req.email,
            username=req.username, domain=req.domain
        )
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed})
    except Exception as e:
        return fail(str(e), 500)

# ── FIR Generator ─────────────────────────────────────────────────────────────
@app.post("/api/fir")
def generate_fir(req: FIRRequest):
    if not req.target:
        return fail("Target required for FIR generation")
    try:
        t0 = time.time()
        result = fir_run(
            target=req.target,
            intel_data=req.intel_data,
            incident_type=req.incident_type,
            complainant=req.complainant,
            station=req.station,
        )
        elapsed = round(time.time() - t0, 2)
        return ok(result, {"elapsed_seconds": elapsed})
    except Exception as e:
        return fail(str(e), 500)

# ── Graph data — for D3.js network visualization ──────────────────────────────
@app.post("/api/graph")
def build_graph(req: PivotRequest):
    """
    Returns nodes + edges in D3 format for the network graph
    """
    nodes = []
    edges = []
    node_id = 0

    def add_node(label, ntype, detail="", risk=0):
        nonlocal node_id
        n = {"id": node_id, "label": label, "type": ntype,
             "detail": detail, "risk": risk}
        nodes.append(n)
        node_id += 1
        return n["id"]

    def add_edge(src, tgt, label=""):
        edges.append({"source": src, "target": tgt, "label": label})

    # Central investigation node
    center = add_node("Investigation", "root", "Central case node")

    if req.phone:
        pid = add_node(req.phone, "phone", "Phone number", risk=50)
        add_edge(center, pid, "phone")
        # WhatsApp node
        wa_id = add_node("WhatsApp", "social", f"wa.me/{req.phone.replace('+','')}")
        add_edge(pid, wa_id, "check")
        tg_id = add_node("Telegram", "social", f"t.me/+{req.phone.replace('+','')}")
        add_edge(pid, tg_id, "check")

    if req.email:
        eid = add_node(req.email, "email", "Email address", risk=30)
        add_edge(center, eid, "email")
        parts = req.email.split("@")
        if len(parts) == 2:
            uname_id = add_node(f"@{parts[0]}", "username", "Username from email")
            add_edge(eid, uname_id, "username")
            dom_id = add_node(parts[1], "domain", "Email domain")
            add_edge(eid, dom_id, "domain")

    if req.username:
        uid = add_node(f"@{req.username}", "username", "Social username")
        add_edge(center, uid, "username")

    if req.domain:
        did = add_node(req.domain, "domain", "Web domain")
        add_edge(center, did, "domain")

    return ok({"nodes": nodes, "edges": edges,
               "meta": {"node_count": len(nodes), "edge_count": len(edges)}})

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
