"""
Unified Bank Server Portal — `/bankserver`

A self-contained banking portal where users:
1. Register real bank accounts
2. Login and view their dashboard
3. Receive email verification when someone else logs in
4. Attacker is silently redirected to Mirror Sandbox on rejection

All accounts stored in BankAccount table, shared with SOC-AML.
"""

from __future__ import annotations

import os
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db
from models import BankAccount, LiveAttackLog, LoginVerification

router = APIRouter(tags=["Bank Server Portal"])

# ── In-Memory Attack Trackers ────────────────────────────────
from collections import defaultdict
import time as _time

_failed_logins: dict = defaultdict(list)  # {ip: [timestamps]}
_transfer_tracker: dict = defaultdict(list)  # {session_id: [timestamps]}

BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = 300  # 5 minutes
RAPID_FIRE_THRESHOLD = 3
RAPID_FIRE_WINDOW = 120  # 2 minutes


# ── API Models ───────────────────────────────────────────────
class RegisterRequest(BaseModel):
    holder_name: str
    phone: str
    email: str
    username: str
    password: str
    ifsc: str = "DEMO0001234"
    city: str = "Chennai"

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    to_name: str
    to_phone: str = ""
    to_ifsc: str = ""
    to_upi: str = ""
    amount: float
    method: str = "IMPS"
    session_id: str = ""


# ── Helpers ──────────────────────────────────────────────────
def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _generate_account_number() -> str:
    import random
    return f"1001{random.randint(200000, 999999)}"


def _send_verification_email(to_email: str, holder_name: str, login_ip: str, session_id: str, server_host: str):
    """Send login verification email with approve/reject links."""
    smtp_email = os.getenv("SMTP_EMAIL", "")
    smtp_password = os.getenv("SMTP_APP_PASSWORD", "")
    if not smtp_email or not smtp_password:
        print("[EMAIL] SMTP not configured — skipping email")
        return False

    approve_url = f"http://{server_host}/bankserver/verify/approve/{session_id}"
    reject_url = f"http://{server_host}/bankserver/verify/reject/{session_id}"

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
        <div style="background:#dc2626;color:white;padding:16px;border-radius:8px 8px 0 0;text-align:center;">
            <h2 style="margin:0;">⚠️ Login Alert — SecureNet Banking</h2>
        </div>
        <div style="background:#1e293b;color:#e2e8f0;padding:24px;border-radius:0 0 8px 8px;">
            <p>Hello <strong>{holder_name}</strong>,</p>
            <p>Someone just logged into your bank account from:</p>
            <div style="background:#0f172a;padding:12px;border-radius:6px;margin:12px 0;">
                <strong style="color:#f59e0b;">IP Address:</strong> <code style="color:#ef4444;">{login_ip}</code>
            </div>
            <p><strong>Was this you?</strong></p>
            <div style="text-align:center;margin:20px 0;">
                <a href="{approve_url}" style="display:inline-block;padding:12px 24px;background:#22c55e;color:white;text-decoration:none;border-radius:6px;font-weight:bold;margin:0 8px;">✅ Yes, it's me</a>
                <a href="{reject_url}" style="display:inline-block;padding:12px 24px;background:#dc2626;color:white;text-decoration:none;border-radius:6px;font-weight:bold;margin:0 8px;">🚫 No, BLOCK them!</a>
            </div>
            <p style="color:#94a3b8;font-size:12px;">If you did not initiate this login, click "No, BLOCK them" immediately. The suspicious session will be trapped and monitored.</p>
        </div>
        <p style="color:#64748b;font-size:10px;text-align:center;margin-top:12px;">SOC-AML Risk Engine — SecureNet Banking Security</p>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"⚠️ Login Alert — Someone accessed your account from {login_ip}"
    msg["From"] = f"SecureNet Banking <{smtp_email}>"
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "587"))) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
        print(f"[EMAIL] Verification sent to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL] Failed: {e}")
        return False


def _log_attack(db: Session, event_type: str, ip: str, ua: str, **kwargs):
    log = LiveAttackLog(
        event_id=f"ATK-{uuid.uuid4().hex[:8].upper()}",
        event_type=event_type,
        attacker_ip=ip,
        user_agent=ua,
        target_account=kwargs.get("target_account"),
        target_holder=kwargs.get("target_holder"),
        destination_account=kwargs.get("destination_account"),
        destination_name=kwargs.get("destination_name"),
        amount=kwargs.get("amount"),
        transfer_method=kwargs.get("transfer_method"),
        risk_score=kwargs.get("risk_score", 0.95),
        status=kwargs.get("status", "INTERCEPTED"),
        details=kwargs.get("details"),
    )
    db.add(log)
    db.commit()
    return log


# ── HTML Portal ──────────────────────────────────────────────
@router.get("/bankserver", response_class=HTMLResponse)
async def bank_server_portal():
    return BANK_SERVER_HTML


# ── API Endpoints ────────────────────────────────────────────
@router.post("/bankserver/api/register")
async def register_account(req: RegisterRequest, db: Session = Depends(get_db)):
    """Create a new bank account."""
    existing = db.query(BankAccount).filter(BankAccount.login_username == req.username).first()
    if existing:
        return JSONResponse(status_code=400, content={"error": "Username already exists"})

    acct_number = _generate_account_number()
    while db.query(BankAccount).filter(BankAccount.account_number == acct_number).first():
        acct_number = _generate_account_number()

    account = BankAccount(
        account_number=acct_number,
        holder_name=req.holder_name,
        phone=req.phone,
        email=req.email,
        login_username=req.username,
        login_password=req.password,
        balance=1000000.0,
        ifsc=req.ifsc,
        city=req.city,
    )
    db.add(account)
    db.commit()

    return {
        "success": True,
        "message": f"Account created for {req.holder_name}",
        "account_number": acct_number,
    }


@router.post("/bankserver/api/login")
async def login_account(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login — creates a verification request and sends email to real user."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")

    account = db.query(BankAccount).filter(BankAccount.login_username == req.username).first()
    if not account or account.login_password != req.password:
        # ── BRUTE FORCE DETECTION ──
        now = _time.time()
        _failed_logins[ip].append(now)
        # Clean old entries
        _failed_logins[ip] = [t for t in _failed_logins[ip] if now - t < BRUTE_FORCE_WINDOW]
        if len(_failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
            target_name = account.holder_name if account else req.username
            target_acct = account.account_number if account else "UNKNOWN"
            _log_attack(db, "BRUTE_FORCE", ip, ua,
                        target_account=target_acct,
                        target_holder=target_name,
                        details=f"Brute force: {len(_failed_logins[ip])} failed logins in {BRUTE_FORCE_WINDOW//60}min from IP {ip}",
                        status="DETECTED", risk_score=0.88)
            _failed_logins[ip] = []  # Reset after logging
        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})

    session_id = f"SESS-{uuid.uuid4().hex[:12].upper()}"

    # ── GEO-ANOMALY DETECTION ──
    if ip not in ("127.0.0.1", "::1", "localhost"):
        _log_attack(db, "GEO_ANOMALY", ip, ua,
                    target_account=account.account_number,
                    target_holder=account.holder_name,
                    details=f"Login from external IP {ip} — account registered in {account.city}. Possible geo-anomaly.",
                    status="FLAGGED", risk_score=0.72)

    # Expire ALL old verification sessions for this account
    db.query(LoginVerification).filter(
        LoginVerification.account_number == account.account_number,
        LoginVerification.status.in_(["PENDING", "APPROVED"]),
    ).update({"status": "EXPIRED"}, synchronize_session="fetch")

    # Create fresh login verification record
    verification = LoginVerification(
        session_id=session_id,
        account_number=account.account_number,
        holder_name=account.holder_name,
        login_ip=ip,
        user_agent=ua,
        status="PENDING",
    )
    db.add(verification)
    db.commit()

    # Send verification email
    server_host = request.headers.get("Host", "localhost:8000")
    email_sent = _send_verification_email(
        to_email=account.email or "",
        holder_name=account.holder_name,
        login_ip=ip,
        session_id=session_id,
        server_host=server_host,
    )

    return {
        "success": True,
        "session_id": session_id,
        "account": {
            "number": account.account_number,
            "holder": account.holder_name,
            "balance": account.balance,
            "ifsc": account.ifsc,
            "city": account.city,
            "phone": account.phone,
            "email": account.email,
        },
        "verification": "PENDING",
        "email_sent": email_sent,
    }


@router.get("/bankserver/api/session-status/{session_id}")
async def get_session_status(session_id: str, db: Session = Depends(get_db)):
    """Poll session verification status."""
    v = db.query(LoginVerification).filter(LoginVerification.session_id == session_id).first()
    if not v:
        return {"status": "UNKNOWN"}

    # Check if account is under attack (rejected)
    account = db.query(BankAccount).filter(BankAccount.account_number == v.account_number).first()
    is_sandboxed = account.is_under_attack if account else False

    return {
        "status": v.status,
        "is_sandboxed": is_sandboxed,
        "session_id": session_id,
    }


@router.get("/bankserver/verify/approve/{session_id}", response_class=HTMLResponse)
async def verify_approve(session_id: str, db: Session = Depends(get_db)):
    """User clicked 'Yes it's me' in the email."""
    v = db.query(LoginVerification).filter(LoginVerification.session_id == session_id).first()
    if not v:
        return "<h2>Invalid or expired verification link.</h2>"

    v.status = "APPROVED"
    v.responded_at = datetime.now(timezone.utc)
    db.commit()

    return """
    <html><head><title>Thank You</title></head><body style="margin:0;background:#0f172a;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="max-width:400px;text-align:center;background:#052e16;color:#22c55e;padding:48px;border-radius:16px;border:1px solid #22c55e;">
        <div style="font-size:64px;margin-bottom:16px;">✅</div>
        <h1 style="font-size:24px;margin-bottom:12px;">Thank You!</h1>
        <p style="color:#86efac;font-size:14px;line-height:1.6;">Your login has been verified successfully.<br>You can safely close this page.</p>
        <p style="color:#475569;font-size:11px;margin-top:20px;">SecureNet Banking — Session Approved</p>
    </div>
    </body></html>
    """


@router.get("/bankserver/verify/reject/{session_id}", response_class=HTMLResponse)
async def verify_reject(session_id: str, request: Request, db: Session = Depends(get_db)):
    """User clicked 'No, block them!' in the email — activate Mirror Sandbox."""
    v = db.query(LoginVerification).filter(LoginVerification.session_id == session_id).first()
    if not v:
        return "<h2>Invalid or expired verification link.</h2>"

    v.status = "REJECTED"
    v.responded_at = datetime.now(timezone.utc)

    # Mark account as under attack → triggers sandbox mode
    account = db.query(BankAccount).filter(BankAccount.account_number == v.account_number).first()
    if account:
        account.is_under_attack = True

    # Log the attack
    _log_attack(db, "UNAUTHORIZED_LOGIN", v.login_ip, v.user_agent or "",
                target_account=v.account_number,
                target_holder=v.holder_name,
                details=f"Login REJECTED by real user — attacker redirected to Mirror Sandbox. IP: {v.login_ip}",
                status="SANDBOX_REDIRECT", risk_score=0.98)

    db.commit()

    return """
    <html><head><title>Threat Blocked</title></head><body style="margin:0;background:#0f172a;font-family:Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="max-width:450px;text-align:center;background:#450a0a;color:#ef4444;padding:48px;border-radius:16px;border:1px solid #ef4444;">
        <div style="font-size:64px;margin-bottom:16px;">🛡️</div>
        <h1 style="font-size:24px;margin-bottom:12px;">Attacker Blocked!</h1>
        <p style="color:#fca5a5;font-size:14px;line-height:1.6;">The suspicious login has been intercepted.<br>The attacker is now in our <strong style="color:#f59e0b;">Mirror Sandbox</strong>.</p>
        <div style="background:#0f172a;border-radius:8px;padding:16px;margin:20px 0;text-align:left;">
            <p style="color:#f59e0b;font-size:12px;font-weight:bold;margin-bottom:8px;">🔍 What happens now:</p>
            <ul style="color:#94a3b8;font-size:11px;line-height:2;padding-left:16px;">
                <li>Attacker sees a <strong>fake dashboard</strong> — thinks they're in</li>
                <li>All their actions are <strong>recorded & monitored</strong></li>
                <li>SOC-AML team has been <strong>alerted in real-time</strong></li>
                <li>Your real account is <strong>100% safe</strong></li>
            </ul>
        </div>
        <p style="color:#475569;font-size:11px;">SecureNet Banking — SOC-AML Threat Response Active</p>
    </div>
    </body></html>
    """


@router.post("/bankserver/api/transfer")
async def bank_server_transfer(req: TransferRequest, request: Request, db: Session = Depends(get_db)):
    """Transfer — checks if session is sandboxed; if so, logs as attack."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")

    # Check if this session is sandboxed
    is_sandboxed = False
    if req.session_id:
        v = db.query(LoginVerification).filter(LoginVerification.session_id == req.session_id).first()
        if v and v.status == "REJECTED":
            is_sandboxed = True
        account = db.query(BankAccount).filter(BankAccount.account_number == req.from_account).first()
        if account and account.is_under_attack:
            is_sandboxed = True

    if is_sandboxed:
        # SANDBOX MODE — log everything, return fake success
        mule_detail = f"Phone: {req.to_phone}, IFSC: {req.to_ifsc}, UPI: {req.to_upi}"
        _log_attack(db, "TRANSFER_ATTEMPT", ip, ua,
                     target_account=req.from_account,
                     destination_account=req.to_account,
                     destination_name=req.to_name,
                     amount=req.amount,
                     transfer_method=req.method,
                     details=f"SANDBOX Transfer ₹{req.amount:,.2f} via {req.method} to {req.to_name} ({req.to_account}) | {mule_detail}",
                     status="SANDBOX_REDIRECT", risk_score=0.97)

        # ── RAPID-FIRE TRANSFER DETECTION ──
        now = _time.time()
        sid = req.session_id or ip
        _transfer_tracker[sid].append(now)
        _transfer_tracker[sid] = [t for t in _transfer_tracker[sid] if now - t < RAPID_FIRE_WINDOW]
        if len(_transfer_tracker[sid]) >= RAPID_FIRE_THRESHOLD:
            total_amt = req.amount * len(_transfer_tracker[sid])
            _log_attack(db, "RAPID_TRANSFERS", ip, ua,
                        target_account=req.from_account,
                        amount=total_amt,
                        details=f"Rapid-fire: {len(_transfer_tracker[sid])} transfers in {RAPID_FIRE_WINDOW//60}min | Total: ₹{total_amt:,.2f}",
                        status="DETECTED", risk_score=0.92)
            _transfer_tracker[sid] = []

        # ── CROSS-ACCOUNT MULE RING DETECTION ──
        if req.to_account:
            same_dest = db.query(LiveAttackLog).filter(
                LiveAttackLog.destination_account == req.to_account,
                LiveAttackLog.target_account != req.from_account,
                LiveAttackLog.event_type == "TRANSFER_ATTEMPT",
            ).first()
            if same_dest:
                _log_attack(db, "MULE_RING_DETECTED", ip, ua,
                            target_account=req.from_account,
                            destination_account=req.to_account,
                            destination_name=req.to_name,
                            amount=req.amount,
                            details=f"Mule ring: Destination {req.to_account} ({req.to_name}) also targeted by account {same_dest.target_account}",
                            status="CONFIRMED", risk_score=0.99)

        return {
            "success": True,
            "transaction_id": f"TXN-{uuid.uuid4().hex[:8].upper()}",
            "message": "Transfer processed successfully",
            "amount": req.amount,
            "status": "COMPLETED",
        }
    else:
        # REAL MODE — check balance and deduct
        account = db.query(BankAccount).filter(BankAccount.account_number == req.from_account).first()
        if not account:
            return JSONResponse(status_code=400, content={"success": False, "error": "Account not found"})
        if req.amount > account.balance:
            return JSONResponse(status_code=400, content={
                "success": False,
                "error": f"Insufficient balance. Available: ₹{account.balance:,.2f}, Requested: ₹{req.amount:,.2f}"
            })
        # Deduct balance
        account.balance -= req.amount
        db.commit()
        return {
            "success": True,
            "transaction_id": f"TXN-{uuid.uuid4().hex[:8].upper()}",
            "message": "Transfer processed successfully",
            "amount": req.amount,
            "new_balance": account.balance,
            "status": "COMPLETED",
        }


# ── Money Addon (Bank Official) ──────────────────────────────
class MoneyAddonRequest(BaseModel):
    account_number: str
    username: str
    password: str
    action: str  # "add" or "withdraw"
    amount: float


@router.post("/bankserver/api/money-addon")
async def money_addon(req: MoneyAddonRequest, db: Session = Depends(get_db)):
    """Bank official endpoint to add or withdraw money from an account."""
    # Authenticate with account credentials
    account = db.query(BankAccount).filter(
        BankAccount.account_number == req.account_number,
        BankAccount.login_username == req.username,
        BankAccount.login_password == req.password,
    ).first()

    if not account:
        return JSONResponse(status_code=401, content={
            "success": False, "error": "Invalid account number or credentials"
        })

    if req.amount <= 0:
        return JSONResponse(status_code=400, content={
            "success": False, "error": "Amount must be greater than 0"
        })

    if req.action == "add":
        account.balance += req.amount
        db.commit()
        return {
            "success": True,
            "message": f"₹{req.amount:,.2f} added to account {account.account_number}",
            "new_balance": account.balance,
            "holder_name": account.holder_name,
        }
    elif req.action == "withdraw":
        if req.amount > account.balance:
            return JSONResponse(status_code=400, content={
                "success": False,
                "error": f"Insufficient balance. Available: ₹{account.balance:,.2f}"
            })
        account.balance -= req.amount
        db.commit()
        return {
            "success": True,
            "message": f"₹{req.amount:,.2f} withdrawn from account {account.account_number}",
            "new_balance": account.balance,
            "holder_name": account.holder_name,
        }
    else:
        return JSONResponse(status_code=400, content={
            "success": False, "error": "Invalid action. Use 'add' or 'withdraw'"
        })


@router.get("/bankserver/api/accounts")
async def list_accounts(db: Session = Depends(get_db)):
    """List all registered accounts for the SOC dashboard."""
    accounts = db.query(BankAccount).all()
    return [
        {
            "account_number": a.account_number,
            "holder_name": a.holder_name,
            "city": a.city,
            "phone": a.phone,
            "email": a.email,
            "ifsc": a.ifsc,
            "balance": a.balance,
            "is_under_attack": a.is_under_attack,
        }
        for a in accounts
    ]


# ── HTML Portal (self-contained) ────────────────────────────
BANK_SERVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureNet Banking — Internet Banking</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }

  /* FORMS */
  .form-container { display: flex; align-items: center; justify-content: center; min-height: 80vh; padding: 20px; width: 100%; }
  .form-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 16px; padding: 40px; width: 100%; max-width: 500px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
  .bank-logo { text-align: center; margin-bottom: 30px; }
  .bank-logo h1 { font-size: 22px; font-weight: 700; background: linear-gradient(90deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 2px; }
  .bank-logo p { font-size: 11px; color: #64748b; margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }

  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 11px; color: #94a3b8; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
  .form-group input, .form-group select { width: 100%; padding: 12px 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 14px; transition: all 0.2s; outline: none; }
  .form-group input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

  .btn-primary { width: 100%; padding: 14px; background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.3s; letter-spacing: 1px; text-transform: uppercase; margin-top: 8px; }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,0.4); }
  .btn-success { background: linear-gradient(135deg, #22c55e, #16a34a); }
  .btn-success:hover { box-shadow: 0 6px 20px rgba(34,197,94,0.4); }

  .msg { text-align: center; margin-top: 12px; font-size: 12px; display: none; padding: 10px; border-radius: 6px; }
  .msg.error { color: #ef4444; background: #450a0a; display: block; }
  .msg.success { color: #22c55e; background: #052e16; display: block; }

  .secure-badge { text-align: center; margin-top: 16px; font-size: 10px; color: #475569; }
  .secure-badge span { color: #22c55e; }

  /* SKELETON LOADING */
  .skeleton-bar { background: linear-gradient(90deg, #1e293b 25%, #334155 50%, #1e293b 75%); background-size: 200% 100%; animation: shimmer 1.5s infinite; }
  .skeleton-pulse { animation: pulse 2s infinite; }
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  .spinner { width: 16px; height: 16px; border: 2px solid #334155; border-top-color: #f59e0b; border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* DASHBOARD */
  .dashboard { display: none; padding: 20px; max-width: 900px; margin: 0 auto; }
  .dash-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: #1e293b; border: 1px solid #334155; border-radius: 12px; margin-bottom: 20px; }
  .dash-header h2 { font-size: 16px; font-weight: 600; }
  .btn-logout { padding: 8px 16px; background: #dc2626; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }

  .account-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
  .balance-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1.5px; }
  .balance { font-size: 36px; font-weight: 700; color: #22c55e; margin: 8px 0; }
  .acct-details { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px; }
  .detail { font-size: 11px; color: #94a3b8; }
  .detail strong { display: block; color: #e2e8f0; font-size: 13px; margin-top: 2px; }

  .transfer-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; }
  .transfer-card h3 { font-size: 14px; font-weight: 600; margin-bottom: 16px; color: #3b82f6; }

  .success-banner { display: none; background: #052e16; border: 1px solid #22c55e; border-radius: 8px; padding: 16px; margin-top: 16px; text-align: center; }
  .success-banner .check { font-size: 32px; margin-bottom: 8px; }
  .success-banner p { color: #22c55e; font-size: 13px; font-weight: 600; }

  .txn-history { margin-top: 20px; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; }
  .txn-history h3 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: #f59e0b; }
  .txn-item { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #334155; font-size: 12px; }
  .txn-item:last-child { border-bottom: none; }
  .txn-item .txn-to { color: #94a3b8; }
  .txn-item .txn-amt { color: #ef4444; font-weight: 600; }
</style>
</head>
<body>

<!-- LANDING PAGE -->
<div id="landingSection">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;">
    <div style="text-align:center;max-width:700px;width:100%;">
      <div style="margin-bottom:40px;">
        <div style="font-size:48px;margin-bottom:12px;">🏦</div>
        <h1 style="font-size:28px;font-weight:700;background:linear-gradient(90deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:2px;">SecureNet Banking</h1>
        <p style="color:#64748b;font-size:13px;margin-top:8px;letter-spacing:1px;text-transform:uppercase;">Trusted Internet Banking • RBI Regulated</p>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
        <!-- Create Account Card -->
        <div onclick="showPage('register')" style="cursor:pointer;background:linear-gradient(145deg,#052e16,#0f172a);border:2px solid #22c55e;border-radius:16px;padding:40px 24px;transition:all 0.3s;text-align:center;" onmouseover="this.style.transform='translateY(-4px)';this.style.boxShadow='0 12px 40px rgba(34,197,94,0.3)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
          <div style="font-size:40px;margin-bottom:16px;">📋</div>
          <h2 style="font-size:18px;color:#22c55e;font-weight:700;margin-bottom:8px;">Create Account</h2>
          <p style="color:#94a3b8;font-size:12px;line-height:1.6;">Open a new bank account with full KYC verification and secure credentials</p>
        </div>
        <!-- Login Card -->
        <div onclick="showPage('login')" style="cursor:pointer;background:linear-gradient(145deg,#172554,#0f172a);border:2px solid #3b82f6;border-radius:16px;padding:40px 24px;transition:all 0.3s;text-align:center;" onmouseover="this.style.transform='translateY(-4px)';this.style.boxShadow='0 12px 40px rgba(59,130,246,0.3)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
          <div style="font-size:40px;margin-bottom:16px;">🔐</div>
          <h2 style="font-size:18px;color:#3b82f6;font-weight:700;margin-bottom:8px;">Login</h2>
          <p style="color:#94a3b8;font-size:12px;line-height:1.6;">Access your existing account with username and password authentication</p>
        </div>
      </div>
      <div style="margin-top:32px;color:#475569;font-size:10px;">🔒 256-bit SSL Encrypted • All transactions monitored by SOC-AML Engine</div>
    </div>
  </div>
</div>

<!-- LOGIN PAGE -->
<div id="loginSection" style="display:none;">
  <div class="form-container">
    <div class="form-card">
      <div style="margin-bottom:16px;"><a href="#" onclick="showPage('landing');return false;" style="color:#64748b;font-size:12px;text-decoration:none;">← Back to Home</a></div>
      <div class="bank-logo">
        <h1>🔐 Sign In</h1>
        <p>Internet Banking Login</p>
      </div>
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="loginUser" placeholder="Enter your username" autocomplete="off">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="loginPass" placeholder="Enter your password">
      </div>
      <button class="btn-primary" onclick="doLogin()">Sign In Securely</button>
      <div class="msg" id="loginMsg"></div>
      <div class="secure-badge"><span>🔒</span> 256-bit SSL Encrypted • RBI Regulated</div>
      <div style="text-align:center;margin-top:16px;font-size:12px;color:#64748b;">Don't have an account? <a href="#" onclick="showPage('register');return false;" style="color:#3b82f6;text-decoration:none;">Create one</a></div>
    </div>
  </div>
</div>

<!-- REGISTER PAGE -->
<div id="registerSection" style="display:none;">
  <div class="form-container">
    <div class="form-card" style="max-width:560px;">
      <div style="margin-bottom:16px;"><a href="#" onclick="showPage('landing');return false;" style="color:#64748b;font-size:12px;text-decoration:none;">← Back to Home</a></div>
      <div class="bank-logo">
        <h1>📋 Create Account</h1>
        <p>Open a New Bank Account</p>
      </div>
      <div class="form-group">
        <label>Full Name (as per Aadhaar)</label>
        <input type="text" id="regName" placeholder="Your full legal name">
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Mobile Number</label>
          <input type="text" id="regPhone" placeholder="+91-XXXXXXXXXX">
        </div>
        <div class="form-group">
          <label>Email Address</label>
          <input type="email" id="regEmail" placeholder="your@email.com">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Choose Username</label>
          <input type="text" id="regUser" placeholder="Choose a username">
        </div>
        <div class="form-group">
          <label>Choose Password</label>
          <input type="password" id="regPass" placeholder="Min 6 characters">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>IFSC Code</label>
          <input type="text" id="regIFSC" placeholder="e.g. SBIN0001234" value="SBIN0001234">
        </div>
        <div class="form-group">
          <label>City</label>
          <select id="regCity" style="width:100%;padding:12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;">
            <option>Chennai</option><option>Mumbai</option><option>Delhi</option>
            <option>Bangalore</option><option>Hyderabad</option><option>Pune</option>
            <option>Kolkata</option><option>Jaipur</option><option>Kochi</option>
          </select>
        </div>
      </div>
      <button class="btn-primary btn-success" onclick="doRegister()">Open Account</button>
      <div class="msg" id="regMsg"></div>
      <div style="text-align:center;margin-top:16px;font-size:12px;color:#64748b;">Already have an account? <a href="#" onclick="showPage('login');return false;" style="color:#3b82f6;text-decoration:none;">Sign In</a></div>
    </div>
  </div>
</div>

<!-- VERIFICATION LOADING SKELETON -->
<div id="verifyLoadingSection" style="display:none;">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;">
    <div style="text-align:center;max-width:500px;width:100%;">
      <div style="margin-bottom:40px;">
        <div style="font-size:48px;margin-bottom:16px;">🏦</div>
        <h2 style="font-size:22px;font-weight:700;color:#e2e8f0;margin-bottom:8px;">SecureNet Banking</h2>
        <p style="color:#64748b;font-size:13px;">Preparing your secure session...</p>
      </div>
      <!-- Skeleton Loading Bars — looks like dashboard loading -->
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
          <div class="skeleton-bar" style="width:48px;height:48px;border-radius:12px;"></div>
          <div style="flex:1;">
            <div class="skeleton-bar" style="width:70%;height:14px;border-radius:4px;margin-bottom:10px;"></div>
            <div class="skeleton-bar" style="width:45%;height:10px;border-radius:4px;"></div>
          </div>
        </div>
        <div class="skeleton-bar" style="width:100%;height:56px;border-radius:10px;margin-bottom:16px;"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
          <div class="skeleton-bar" style="height:36px;border-radius:8px;"></div>
          <div class="skeleton-bar" style="height:36px;border-radius:8px;"></div>
          <div class="skeleton-bar" style="height:36px;border-radius:8px;"></div>
        </div>
      </div>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;">
        <div class="skeleton-bar" style="width:100%;height:80px;border-radius:8px;margin-bottom:12px;"></div>
        <div class="skeleton-bar" style="width:60%;height:12px;border-radius:4px;"></div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-top:20px;color:#3b82f6;font-size:12px;">
        <div class="spinner" style="border-color:#3b82f6 transparent transparent transparent;"></div>
        <span id="verifyLoadingText">Loading your account...</span>
      </div>
    </div>
  </div>
</div>

<!-- DASHBOARD -->
<div class="dashboard" id="dashSection">
  <div class="dash-header">
    <h2>Welcome, <span id="holderName"></span></h2>
    <button class="btn-logout" onclick="doLogout()">Logout</button>
  </div>

  <!-- Account Balance + Card -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
    <div class="account-card">
      <div class="balance-label">Available Balance</div>
      <div class="balance" id="balanceDisplay">₹0</div>
      <div class="acct-details" style="grid-template-columns:1fr 1fr;">
        <div class="detail">Account No.<strong id="acctNumber"></strong></div>
        <div class="detail">IFSC Code<strong id="acctIFSC"></strong></div>
        <div class="detail">Branch<strong id="acctCity"></strong></div>
        <div class="detail">Account Type<strong>Savings</strong></div>
      </div>
    </div>
    <!-- Debit Card -->
    <div style="background:linear-gradient(135deg,#1e3a5f,#0f172a,#312e81);border:1px solid #3b82f6;border-radius:16px;padding:28px;position:relative;overflow:hidden;">
      <div style="position:absolute;top:-20px;right:-20px;width:100px;height:100px;background:rgba(59,130,246,0.1);border-radius:50%;"></div>
      <div style="position:absolute;bottom:-30px;left:-30px;width:120px;height:120px;background:rgba(139,92,246,0.08);border-radius:50%;"></div>
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;">SecureNet Debit Card</div>
      <div id="cardNumber" style="font-size:18px;font-weight:600;letter-spacing:4px;color:#e2e8f0;margin-bottom:16px;font-family:monospace;">•••• •••• •••• ••••</div>
      <div style="display:flex;justify-content:space-between;align-items:flex-end;">
        <div>
          <div style="font-size:9px;color:#64748b;text-transform:uppercase;">Card Holder</div>
          <div id="cardHolder" style="font-size:12px;color:#e2e8f0;font-weight:600;text-transform:uppercase;"></div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:9px;color:#64748b;text-transform:uppercase;">Valid Thru</div>
          <div style="font-size:12px;color:#e2e8f0;font-weight:600;">12/28</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:9px;color:#64748b;text-transform:uppercase;">CVV</div>
          <div style="font-size:12px;color:#e2e8f0;font-weight:600;">•••</div>
        </div>
      </div>
      <div style="text-align:right;margin-top:12px;font-size:18px;font-weight:700;color:#3b82f6;">VISA</div>
    </div>
  </div>

  <!-- Account Details Grid -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
      <div style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Phone</div>
      <div id="acctPhone" style="font-size:12px;color:#e2e8f0;font-weight:600;margin-top:4px;">—</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
      <div style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Email</div>
      <div id="acctEmail" style="font-size:12px;color:#e2e8f0;font-weight:600;margin-top:4px;word-break:break-all;">—</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
      <div style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Account Status</div>
      <div style="font-size:12px;color:#22c55e;font-weight:600;margin-top:4px;">● Active</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;">
      <div style="font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Last Login</div>
      <div style="font-size:12px;color:#e2e8f0;font-weight:600;margin-top:4px;">Just now</div>
    </div>
  </div>

  <div class="transfer-card">
    <h3>💸 Fund Transfer</h3>
    <div class="form-row">
      <div class="form-group">
        <label>Beneficiary Account No.</label>
        <input type="text" id="toAccount" placeholder="Account Number">
      </div>
      <div class="form-group">
        <label>Beneficiary Full Name</label>
        <input type="text" id="toName" placeholder="Full Name">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Beneficiary Phone</label>
        <input type="text" id="toPhone" placeholder="+91-XXXXXXXXXX">
      </div>
      <div class="form-group">
        <label>Beneficiary IFSC</label>
        <input type="text" id="toIFSC" placeholder="e.g. SBIN0001234">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>UPI ID (optional)</label>
        <input type="text" id="toUPI" placeholder="e.g. name@upi">
      </div>
      <div class="form-group">
        <label>Amount (₹)</label>
        <input type="number" id="txnAmount" placeholder="Enter amount">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Transfer Method</label>
        <select id="txnMethod" style="width:100%;padding:12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;">
          <option>IMPS</option><option>UPI</option><option>NEFT</option><option>RTGS</option>
        </select>
      </div>
      <div class="form-group" style="display:flex;align-items:flex-end">
        <button class="btn-primary btn-success" onclick="doTransfer()" style="margin-top:0">Transfer Now</button>
      </div>
    </div>
    <div class="success-banner" id="successBanner">
      <div class="check">✅</div>
      <p id="successMsg">Transfer Successful!</p>
    </div>
  </div>

  <div class="txn-history">
    <h3>📋 Recent Transactions</h3>
    <div id="txnList"><div style="color:#64748b;font-size:12px;">No recent transactions</div></div>
  </div>
</div>

<script>
const API = window.location.origin;
let currentAccount = null;
let currentSession = null;
let fakeTxns = [];
let verifyPollInterval = null;

function showPage(page) {
  document.getElementById('landingSection').style.display = page === 'landing' ? 'block' : 'none';
  document.getElementById('loginSection').style.display = page === 'login' ? 'block' : 'none';
  document.getElementById('registerSection').style.display = page === 'register' ? 'block' : 'none';
  document.getElementById('verifyLoadingSection').style.display = page === 'verifying' ? 'block' : 'none';
  document.getElementById('dashSection').style.display = page === 'dashboard' ? 'block' : 'none';
}

function genCardNumber(acct) {
  const base = acct || '0000000000';
  return '4' + base.substring(0,3) + ' ' + base.substring(3,7) + ' ' + base.substring(2,6) + ' ' + base.substring(0,4);
}

async function doRegister() {
  const data = {
    holder_name: document.getElementById('regName').value.trim(),
    phone: document.getElementById('regPhone').value.trim(),
    email: document.getElementById('regEmail').value.trim(),
    username: document.getElementById('regUser').value.trim(),
    password: document.getElementById('regPass').value.trim(),
    ifsc: document.getElementById('regIFSC').value.trim(),
    city: document.getElementById('regCity').value,
  };
  if (!data.holder_name || !data.username || !data.password || !data.email) {
    showMsg('regMsg', 'Please fill all required fields.', 'error');
    return;
  }
  try {
    const res = await fetch(API + '/bankserver/api/register', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)
    });
    const result = await res.json();
    if (result.success) {
      showMsg('regMsg', '✅ Account created! Account No: ' + result.account_number + '. You can now sign in.', 'success');
    } else {
      showMsg('regMsg', result.error || 'Registration failed.', 'error');
    }
  } catch { showMsg('regMsg', 'Server error.', 'error'); }
}

async function doLogin() {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value.trim();
  if (!username || !password) return;

  // Show skeleton loading IMMEDIATELY — don't wait for API
  showPage('verifying');

  try {
    const res = await fetch(API + '/bankserver/api/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    const data = await res.json();
    if (data.success) {
      currentAccount = data.account;
      currentSession = data.session_id;

      // Start polling for verification
      startVerifyPoll();
    } else {
      // Login failed — go back to login form
      showPage('login');
      showMsg('loginMsg', data.error || 'Invalid credentials.', 'error');
    }
  } catch {
    showPage('login');
    showMsg('loginMsg', 'Server error.', 'error');
  }
}

function enterDashboard() {
  document.getElementById('holderName').textContent = currentAccount.holder;
  document.getElementById('balanceDisplay').textContent = '₹' + Number(currentAccount.balance).toLocaleString('en-IN');
  document.getElementById('acctNumber').textContent = currentAccount.number;
  document.getElementById('acctIFSC').textContent = currentAccount.ifsc;
  document.getElementById('acctCity').textContent = currentAccount.city;
  document.getElementById('acctPhone').textContent = currentAccount.phone || '—';
  document.getElementById('acctEmail').textContent = currentAccount.email || '—';
  document.getElementById('cardHolder').textContent = currentAccount.holder;
  document.getElementById('cardNumber').textContent = genCardNumber(currentAccount.number);
  showPage('dashboard');
}

function startVerifyPoll() {
  if (verifyPollInterval) clearInterval(verifyPollInterval);
  verifyPollInterval = setInterval(async () => {
    try {
      const res = await fetch(API + '/bankserver/api/session-status/' + currentSession);
      const data = await res.json();
      if (data.status === 'APPROVED') {
        clearInterval(verifyPollInterval);
        document.getElementById('verifyLoadingText').textContent = '✅ Verified! Loading your account...';
        setTimeout(() => { enterDashboard(); }, 1500);
      } else if (data.status === 'REJECTED') {
        // Attacker gets silently redirected to sandbox — they think it's approved
        clearInterval(verifyPollInterval);
        document.getElementById('verifyLoadingText').textContent = '✅ Verified! Loading your account...';
        setTimeout(() => { enterDashboard(); }, 1500);
      }
    } catch {}
  }, 3000);
}

async function doTransfer() {
  const toAccount = document.getElementById('toAccount').value.trim();
  const toName = document.getElementById('toName').value.trim();
  const toPhone = document.getElementById('toPhone').value.trim();
  const toIFSC = document.getElementById('toIFSC').value.trim();
  const toUPI = document.getElementById('toUPI').value.trim();
  const amount = parseFloat(document.getElementById('txnAmount').value);
  const method = document.getElementById('txnMethod').value;

  if (!toAccount || !toName || !amount || amount <= 0) {
    alert('Please fill all required fields.');
    return;
  }

  try {
    const res = await fetch(API + '/bankserver/api/transfer', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        from_account: currentAccount.number,
        to_account: toAccount, to_name: toName,
        to_phone: toPhone, to_ifsc: toIFSC, to_upi: toUPI,
        amount, method, session_id: currentSession
      })
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById('successBanner').style.display = 'block';
      document.getElementById('successMsg').textContent =
        '₹' + amount.toLocaleString('en-IN') + ' transferred to ' + toName + ' • TXN: ' + data.transaction_id;

      fakeTxns.unshift({to: toName, amount, method, id: data.transaction_id});
      renderTxns();

      // Update balance from server response
      if (data.new_balance !== undefined) {
        currentAccount.balance = data.new_balance;
      } else {
        currentAccount.balance -= amount;
      }
      document.getElementById('balanceDisplay').textContent = '₹' + Math.max(0, currentAccount.balance).toLocaleString('en-IN');

      ['toAccount','toName','toPhone','toIFSC','toUPI','txnAmount'].forEach(id => document.getElementById(id).value = '');
      setTimeout(() => { document.getElementById('successBanner').style.display = 'none'; }, 5000);
    } else {
      alert(data.error || 'Transfer failed.');
    }
  } catch { alert('Transfer failed.'); }
}

function renderTxns() {
  const list = document.getElementById('txnList');
  if (fakeTxns.length === 0) {
    list.innerHTML = '<div style="color:#64748b;font-size:12px;">No recent transactions</div>';
    return;
  }
  list.innerHTML = fakeTxns.map(t =>
    '<div class="txn-item"><span class="txn-to">' + t.method + ' → ' + t.to + '</span><span class="txn-amt">-₹' + t.amount.toLocaleString('en-IN') + '</span></div>'
  ).join('');
}

function doLogout() {
  currentAccount = null;
  currentSession = null;
  fakeTxns = [];
  if (verifyPollInterval) clearInterval(verifyPollInterval);
  showPage('landing');
}

function showMsg(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg ' + type;
  el.style.display = 'block';
  if (type === 'success') setTimeout(() => { el.style.display = 'none'; }, 8000);
}
</script>
</body>
</html>"""
