"""
Live Attack Simulation — Fake Bank Portal

Serves a self-contained bank portal HTML page at /bank.
Captures real attacker IP, User-Agent, and all actions.
Every transfer is silently redirected to the Mirror Sandbox.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db
from models import BankAccount, LiveAttackLog

router = APIRouter(tags=["Bank Portal (Live Demo)"])


# ── API Models ───────────────────────────────────────────────
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


def _guess_location(ip: str) -> str:
    """Guess attacker location from IP for demo purposes."""
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Local Network — Same WiFi (LAN Attack)"
    if ip in ("127.0.0.1", "::1", "localhost"):
        return "Localhost — Same Machine"
    return f"External Network — {ip}"


def _get_client_ip(request: Request) -> str:
    """Extract real client IP."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _log_attack(db: Session, event_type: str, ip: str, ua: str, **kwargs):
    """Log an attack event."""
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


# ── Bank Portal HTML ─────────────────────────────────────────
@router.get("/bank", response_class=HTMLResponse)
async def bank_portal():
    """Serve the fake bank portal — a single self-contained HTML page."""
    return BANK_PORTAL_HTML


# ── Bank API Endpoints ───────────────────────────────────────
@router.post("/bank/api/login")
async def bank_login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Validate login, capture attacker IP."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")

    account = db.query(BankAccount).filter(
        BankAccount.login_username == req.username
    ).first()

    if not account or account.login_password != req.password:
        _log_attack(db, "LOGIN_FAILED", ip, ua,
                     details=f"Failed login: username={req.username}",
                     status="BLOCKED", risk_score=0.85)
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid credentials", "blocked": False}
        )

    # Mark account under attack
    account.is_under_attack = True
    db.commit()

    _log_attack(db, "LOGIN_SUCCESS", ip, ua,
                 target_account=account.account_number,
                 target_holder=account.holder_name,
                 details=f"Successful login to {account.holder_name}'s account",
                 status="MONITORING", risk_score=0.92)

    return {
        "success": True,
        "account": {
            "number": account.account_number,
            "holder": account.holder_name,
            "balance": account.balance,
            "ifsc": account.ifsc,
            "city": account.city,
        },
        "session": f"SESS-{uuid.uuid4().hex[:12].upper()}"
    }


@router.post("/bank/api/transfer")
async def bank_transfer(req: TransferRequest, request: Request, db: Session = Depends(get_db)):
    """Intercept transfer — log to sandbox, return fake success."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")

    mule_detail = f"Phone: {req.to_phone}, IFSC: {req.to_ifsc}, UPI: {req.to_upi}"
    _log_attack(db, "TRANSFER_ATTEMPT", ip, ua,
                 target_account=req.from_account,
                 destination_account=req.to_account,
                 destination_name=req.to_name,
                 amount=req.amount,
                 transfer_method=req.method,
                 details=f"Transfer ₹{req.amount:,.2f} via {req.method} to {req.to_name} ({req.to_account}) | {mule_detail}",
                 status="SANDBOX_REDIRECT", risk_score=0.97)

    # Return fake success — attacker thinks it worked
    return {
        "success": True,
        "transaction_id": f"TXN-{uuid.uuid4().hex[:8].upper()}",
        "message": "Transfer processed successfully",
        "amount": req.amount,
        "status": "COMPLETED",
        "_sandbox": True  # hidden flag
    }


@router.get("/bank/api/balance/{account_number}")
async def bank_balance(account_number: str, request: Request, db: Session = Depends(get_db)):
    """Return fake balance, log the check."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")

    account = db.query(BankAccount).filter(
        BankAccount.account_number == account_number
    ).first()

    if not account:
        return JSONResponse(status_code=404, content={"error": "Account not found"})

    _log_attack(db, "BALANCE_CHECK", ip, ua,
                 target_account=account.account_number,
                 target_holder=account.holder_name,
                 details=f"Balance check on {account.holder_name}'s account",
                 status="MONITORING", risk_score=0.88)

    return {
        "account": account.account_number,
        "holder": account.holder_name,
        "balance": account.balance,
        "currency": "INR",
    }


# ── Live Attack Feed (for SOC Dashboard) ─────────────────────
@router.get("/api/v1/live-attacks")
async def get_live_attacks(limit: int = 50, db: Session = Depends(get_db)):
    """Return recent attack events for the SOC dashboard."""
    attacks = (
        db.query(LiveAttackLog)
        .order_by(LiveAttackLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "event_id": a.event_id,
            "event_type": a.event_type,
            "attacker_ip": a.attacker_ip,
            "user_agent": a.user_agent,
            "target_account": a.target_account,
            "target_holder": a.target_holder,
            "destination_account": a.destination_account,
            "destination_name": a.destination_name,
            "amount": a.amount,
            "transfer_method": a.transfer_method,
            "risk_score": a.risk_score,
            "status": a.status,
            "details": a.details,
            "timestamp": a.timestamp.isoformat() + "Z",
            "attacker_location": _guess_location(a.attacker_ip),
        }
        for a in attacks
    ]


@router.get("/api/v1/live-attacks/active")
async def get_active_attacks(db: Session = Depends(get_db)):
    """Check if any accounts are currently under attack."""
    under_attack = db.query(BankAccount).filter(BankAccount.is_under_attack == True).all()
    recent_attacks = (
        db.query(LiveAttackLog)
        .order_by(LiveAttackLog.timestamp.desc())
        .limit(5)
        .all()
    )

    return {
        "is_active": len(under_attack) > 0,
        "accounts_under_attack": [
            {
                "account_number": a.account_number,
                "holder_name": a.holder_name,
                "city": a.city,
            }
            for a in under_attack
        ],
        "recent_events": [
            {
                "event_id": a.event_id,
                "event_type": a.event_type,
                "attacker_ip": a.attacker_ip,
                "target_holder": a.target_holder,
                "amount": a.amount,
                "status": a.status,
                "timestamp": a.timestamp.isoformat() + "Z",
            }
            for a in recent_attacks
        ],
        "total_attacks": db.query(LiveAttackLog).count(),
    }


# ── Self-contained Bank Portal HTML ──────────────────────────
BANK_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureNet Banking — Internet Banking</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }

  .login-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
  .login-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 16px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
  .bank-logo { text-align: center; margin-bottom: 30px; }
  .bank-logo h1 { font-size: 22px; font-weight: 700; background: linear-gradient(90deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 2px; }
  .bank-logo p { font-size: 11px; color: #64748b; margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }

  .form-group { margin-bottom: 18px; }
  .form-group label { display: block; font-size: 11px; color: #94a3b8; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
  .form-group input { width: 100%; padding: 12px 16px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 14px; transition: all 0.2s; outline: none; }
  .form-group input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }

  .btn-login { width: 100%; padding: 14px; background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.3s; letter-spacing: 1px; text-transform: uppercase; }
  .btn-login:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,0.4); }
  .btn-login:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  .error-msg { color: #ef4444; font-size: 12px; text-align: center; margin-top: 12px; display: none; }
  .secure-badge { text-align: center; margin-top: 20px; font-size: 10px; color: #475569; }
  .secure-badge span { color: #22c55e; }

  /* Dashboard styles */
  .dashboard { display: none; padding: 20px; max-width: 900px; margin: 0 auto; }
  .dash-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: #1e293b; border: 1px solid #334155; border-radius: 12px; margin-bottom: 20px; }
  .dash-header h2 { font-size: 16px; font-weight: 600; }
  .dash-header .logout { padding: 8px 16px; background: #dc2626; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }

  .account-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
  .account-card .balance-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1.5px; }
  .account-card .balance { font-size: 36px; font-weight: 700; color: #22c55e; margin: 8px 0; }
  .account-card .acct-details { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px; }
  .account-card .detail { font-size: 11px; color: #94a3b8; }
  .account-card .detail strong { display: block; color: #e2e8f0; font-size: 13px; margin-top: 2px; }

  .transfer-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; }
  .transfer-card h3 { font-size: 14px; font-weight: 600; margin-bottom: 16px; color: #3b82f6; }
  .transfer-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .btn-transfer { padding: 14px 24px; background: linear-gradient(135deg, #22c55e, #16a34a); color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; width: 100%; margin-top: 8px; letter-spacing: 1px; text-transform: uppercase; }
  .btn-transfer:hover { box-shadow: 0 6px 20px rgba(34,197,94,0.4); }

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

<!-- LOGIN -->
<div class="login-container" id="loginSection">
  <div class="login-card">
    <div class="bank-logo">
      <h1>🏦 SecureNet Banking</h1>
      <p>Internet Banking Portal</p>
    </div>
    <div class="form-group">
      <label>Customer ID / Username</label>
      <input type="text" id="username" placeholder="Enter your Customer ID" autocomplete="off">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="password" placeholder="Enter your Password">
    </div>
    <button class="btn-login" id="loginBtn" onclick="doLogin()">Sign In Securely</button>
    <div class="error-msg" id="loginError">Invalid credentials. Please try again.</div>
    <div class="secure-badge"><span>🔒</span> 256-bit SSL Encrypted • RBI Regulated</div>
  </div>
</div>

<!-- DASHBOARD -->
<div class="dashboard" id="dashSection">
  <div class="dash-header">
    <h2>Welcome, <span id="holderName"></span></h2>
    <button class="logout" onclick="doLogout()">Logout</button>
  </div>

  <div class="account-card">
    <div class="balance-label">Available Balance</div>
    <div class="balance" id="balanceDisplay">₹0</div>
    <div class="acct-details">
      <div class="detail">Account No.<strong id="acctNumber"></strong></div>
      <div class="detail">IFSC Code<strong id="acctIFSC"></strong></div>
      <div class="detail">Branch<strong id="acctCity"></strong></div>
    </div>
  </div>

  <div class="transfer-card">
    <h3>💸 Fund Transfer</h3>
    <div class="transfer-row">
      <div class="form-group">
        <label>Beneficiary Account No.</label>
        <input type="text" id="toAccount" placeholder="Account Number">
      </div>
      <div class="form-group">
        <label>Beneficiary Full Name</label>
        <input type="text" id="toName" placeholder="Full Name">
      </div>
    </div>
    <div class="transfer-row">
      <div class="form-group">
        <label>Beneficiary Phone</label>
        <input type="text" id="toPhone" placeholder="+91-XXXXXXXXXX">
      </div>
      <div class="form-group">
        <label>Beneficiary IFSC</label>
        <input type="text" id="toIFSC" placeholder="e.g. SBIN0001234">
      </div>
    </div>
    <div class="transfer-row">
      <div class="form-group">
        <label>UPI ID (optional)</label>
        <input type="text" id="toUPI" placeholder="e.g. name@upi">
      </div>
      <div class="form-group">
        <label>Amount (₹)</label>
        <input type="number" id="txnAmount" placeholder="Enter amount">
      </div>
    </div>
    <div class="transfer-row">
      <div class="form-group">
        <label>Transfer Method</label>
        <select id="txnMethod" style="width:100%;padding:12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;">
          <option>IMPS</option>
          <option>UPI</option>
          <option>NEFT</option>
          <option>RTGS</option>
        </select>
      </div>
      <div class="form-group" style="display:flex;align-items:flex-end">
        <button class="btn-transfer" onclick="doTransfer()" style="margin-top:0">Transfer Now</button>
      </div>
    </div>
    <div class="success-banner" id="successBanner">
      <div class="check">✅</div>
      <p id="successMsg">Transfer Successful!</p>
    </div>
  </div>

  <div class="txn-history">
    <h3>📋 Recent Transactions</h3>
    <div id="txnList"></div>
  </div>
</div>

<script>
let currentAccount = null;
let fakeTxns = [];
const API = window.location.origin;

async function doLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!username || !password) return;

  document.getElementById('loginBtn').disabled = true;
  document.getElementById('loginBtn').textContent = 'Authenticating...';

  try {
    const res = await fetch(API + '/bank/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    const data = await res.json();

    if (data.success) {
      currentAccount = data.account;
      document.getElementById('loginSection').style.display = 'none';
      document.getElementById('dashSection').style.display = 'block';
      document.getElementById('holderName').textContent = data.account.holder;
      document.getElementById('balanceDisplay').textContent = '₹' + Number(data.account.balance).toLocaleString('en-IN');
      document.getElementById('acctNumber').textContent = data.account.number;
      document.getElementById('acctIFSC').textContent = data.account.ifsc;
      document.getElementById('acctCity').textContent = data.account.city;
    } else {
      document.getElementById('loginError').style.display = 'block';
    }
  } catch {
    document.getElementById('loginError').style.display = 'block';
    document.getElementById('loginError').textContent = 'Server error. Please try again.';
  }

  document.getElementById('loginBtn').disabled = false;
  document.getElementById('loginBtn').textContent = 'Sign In Securely';
}

async function doTransfer() {
  const toAccount = document.getElementById('toAccount').value.trim();
  const toName = document.getElementById('toName').value.trim();
  const amount = parseFloat(document.getElementById('txnAmount').value);
  const method = document.getElementById('txnMethod').value;

  const toPhone = document.getElementById('toPhone').value.trim();
  const toIFSC = document.getElementById('toIFSC').value.trim();
  const toUPI = document.getElementById('toUPI').value.trim();

  if (!toAccount || !toName || !amount || amount <= 0) {
    alert('Please fill all fields.');
    return;
  }

  try {
    const res = await fetch(API + '/bank/api/transfer', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        from_account: currentAccount.number,
        to_account: toAccount,
        to_name: toName,
        to_phone: toPhone,
        to_ifsc: toIFSC,
        to_upi: toUPI,
        amount: amount,
        method: method
      })
    });
    const data = await res.json();

    if (data.success) {
      // Show fake success
      document.getElementById('successBanner').style.display = 'block';
      document.getElementById('successMsg').textContent =
        '₹' + amount.toLocaleString('en-IN') + ' transferred to ' + toName + ' • TXN: ' + data.transaction_id;

      // Add to fake transaction history
      fakeTxns.unshift({to: toName, amount: amount, method: method, id: data.transaction_id});
      renderTxns();

      // Update fake balance (decrease it to look real)
      const newBal = currentAccount.balance - amount;
      currentAccount.balance = newBal;
      document.getElementById('balanceDisplay').textContent = '₹' + Math.max(0, newBal).toLocaleString('en-IN');

      // Clear form
      document.getElementById('toAccount').value = '';
      document.getElementById('toName').value = '';
      document.getElementById('toPhone').value = '';
      document.getElementById('toIFSC').value = '';
      document.getElementById('toUPI').value = '';
      document.getElementById('txnAmount').value = '';

      setTimeout(() => { document.getElementById('successBanner').style.display = 'none'; }, 5000);
    }
  } catch {
    alert('Transfer failed. Try again.');
  }
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
  fakeTxns = [];
  document.getElementById('dashSection').style.display = 'none';
  document.getElementById('loginSection').style.display = 'flex';
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('loginError').style.display = 'none';
}

renderTxns();
</script>
</body>
</html>"""
