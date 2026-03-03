"""
Smart AI Analysis Endpoint — /api/v1/analyze

Hash-based cache to throttle Gemini API calls:
1. SHA-256 hash of request params
2. Check AiCache table
3. If hit → return cached narrative (0 API calls)
4. If miss → single Gemini call → store in cache → return
"""

import hashlib
import json
import os
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import get_db
from models import AiCache, Transaction, CyberLog

logger = logging.getLogger("soc_aml.analyze")

router = APIRouter(prefix="/api/v1", tags=["AI Analysis"])


class AnalyzeRequest(BaseModel):
    user_id: Optional[str] = None
    transaction_id: Optional[str] = None
    ip_address: Optional[str] = None
    threat_title: Optional[str] = None
    amount: Optional[float] = None
    message: Optional[str] = None


class AnalyzeResponse(BaseModel):
    narrative: str
    cached: bool
    request_hash: str
    timestamp: str


def _compute_hash(params: dict) -> str:
    """SHA-256 hash of the request params for cache lookup."""
    canonical = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _build_threat_context(req: AnalyzeRequest, db: Session) -> str:
    """Build a rich text prompt from real database queries."""
    context_parts = []

    if req.transaction_id:
        tx = db.query(Transaction).filter(Transaction.tx_id == req.transaction_id).first()
        if tx:
            context_parts.append(f"""
Transaction Details:
- TX ID: {tx.tx_id}
- Sender: {tx.user_name} ({tx.user_id}) from {tx.city}
- Receiver: {tx.receiver_name} ({tx.receiver_id})
- Amount: ₹{tx.amount:,.2f} via {tx.transfer_method}
- UPI ID: {tx.upi_id or 'N/A'}
- IP: {tx.ip_address}
- Flagged: {tx.is_flagged} — {tx.flag_reason or 'No reason'}
""")

    if req.user_id:
        txns = db.query(Transaction).filter(
            (Transaction.user_id == req.user_id) | (Transaction.receiver_id == req.user_id)
        ).order_by(Transaction.timestamp.desc()).limit(10).all()

        if txns:
            context_parts.append(f"\nRecent transactions for {req.user_id}:")
            for t in txns:
                context_parts.append(
                    f"  - {t.tx_id}: {t.user_name} → {t.receiver_name}, "
                    f"₹{t.amount:,.2f} via {t.transfer_method}, "
                    f"IP: {t.ip_address}, Flagged: {t.is_flagged}"
                )

    if req.ip_address:
        ip_txns = db.query(Transaction).filter(Transaction.ip_address == req.ip_address).all()
        ip_logs = db.query(CyberLog).filter(CyberLog.ip_address == req.ip_address).all()
        context_parts.append(f"\nIP {req.ip_address} activity: {len(ip_txns)} transactions, {len(ip_logs)} cyber logs")

    target_user = req.user_id
    target_ip = req.ip_address
    if target_user or target_ip:
        logs = db.query(CyberLog).filter(
            (CyberLog.user_id == target_user) if target_user else (CyberLog.ip_address == target_ip)
        ).order_by(CyberLog.timestamp.desc()).limit(5).all()

        if logs:
            context_parts.append("\nCorrelated Cyber Alerts:")
            for l in logs:
                context_parts.append(
                    f"  - [{l.severity.upper()}] {l.event_type}: {l.description} "
                    f"(IP: {l.ip_address}, {l.timestamp.isoformat()})"
                )

    return "\n".join(context_parts) if context_parts else "No specific threat context available."


def _generate_fallback_narrative(req: AnalyzeRequest, context: str) -> str:
    """Local fallback when Gemini is unavailable."""
    title = req.threat_title or "Suspicious Activity"
    amount_str = f"₹{req.amount:,.2f}" if req.amount else "undetermined amount"

    return f"""## Threat Analysis: {title}

**Analysis Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC

### Summary
A suspicious pattern has been detected involving {amount_str} in financial transfers potentially linked to cyber breach activity. The system has identified correlated indicators across transaction records and cyber security logs.

### Key Findings
{context}

### Risk Assessment
Based on the available data, this activity pattern is consistent with a **coordinated money mule operation**. The temporal proximity between cyber alerts and high-value transfers, combined with shared IP infrastructure, suggests an organized threat actor.

### Recommended Actions
1. **Immediate**: Freeze associated accounts pending investigation
2. **Short-term**: Escalate to AML compliance team for SAR filing
3. **Long-term**: Add identified IPs and UPI IDs to the watchlist

*This analysis was generated locally. AI-enhanced analysis will resume when the Gemini service is available.*"""


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_threat(req: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Smart cached AI analysis endpoint.
    1. Hash request params
    2. Check cache
    3. If miss → Gemini call → cache → return
    """
    # Build hash from request params
    hash_input = {
        "user_id": req.user_id,
        "transaction_id": req.transaction_id,
        "ip_address": req.ip_address,
        "amount": req.amount,
        "message": req.message,
    }
    request_hash = _compute_hash(hash_input)

    # ── Cache Check ──────────────────────────────────────────
    cached = db.query(AiCache).filter(AiCache.request_hash == request_hash).first()
    if cached:
        logger.info(f"Cache HIT for hash {request_hash[:12]}...")
        return AnalyzeResponse(
            narrative=cached.threat_narrative,
            cached=True,
            request_hash=request_hash,
            timestamp=cached.timestamp.isoformat() + "Z",
        )

    # ── Cache Miss → Build Context + AI Call ─────────────────
    logger.info(f"Cache MISS for hash {request_hash[:12]}... building context")
    context = _build_threat_context(req, db)

    narrative = ""
    api_key = os.getenv("GOOGLE_API_KEY", "")

    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-2.0-flash")

            prompt = f"""You are an elite SOC-AML threat intelligence analyst at an Indian financial institution's Unified Threat Operations Center.

THREAT CONTEXT:
{context}

ANALYST QUERY: {req.message or "Full threat assessment."}

OUTPUT FORMAT — respond in compact, structured markdown:

## 🔴 THREAT CLASSIFICATION
One line: attack type, severity (CRITICAL/HIGH/MEDIUM), confidence %.

## 📊 INTEL SUMMARY
3–5 bullet points max. Each bullet = one key finding. Be precise:
- Breach vector and entry point
- Financial flow: who → who, ₹amount, method (UPI/IMPS/NEFT)
- IP correlation: shared IPs, TOR nodes, VPN detected
- Temporal link: time gap between cyber alert → financial transfer
- Mule ring indicators: layered transfers, rapid succession

## ⚡ IMMEDIATE ACTIONS
Numbered list, 3–4 items max. Be specific (account IDs, IPs, UPI handles to block).

## 🎯 RISK VERDICT
One concise paragraph: Is this a confirmed mule ring? What's the financial exposure? What's the escalation path (RBI SAR, FIU-IND, cyber cell)?

RULES:
- Indian financial context only (INR, UPI, IMPS, NEFT, Aadhaar, PAN, RBI, FIU-IND)
- NO filler text, NO disclaimers, NO "please note"
- Maximum 200 words total. Compact = intelligence, not essays
- Use bold for key values: **amounts**, **IPs**, **account IDs**
- Think like a cyber-forensics officer briefing a SAR filing team"""

            result = model.generate_content(prompt)
            narrative = result.text
            logger.info("Gemini API call successful")
        except Exception as e:
            logger.warning(f"Gemini API failed: {e}. Using fallback.")
            narrative = _generate_fallback_narrative(req, context)
    else:
        logger.info("No GOOGLE_API_KEY set. Using local fallback narrative.")
        narrative = _generate_fallback_narrative(req, context)

    # ── Store in Cache ───────────────────────────────────────
    cache_entry = AiCache(
        request_hash=request_hash,
        threat_narrative=narrative,
        threat_context=json.dumps(hash_input, default=str),
    )
    db.add(cache_entry)
    db.commit()

    return AnalyzeResponse(
        narrative=narrative,
        cached=False,
        request_hash=request_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── Account Report Endpoint ──────────────────────────────────
class AccountReportRequest(BaseModel):
    account_number: str


@router.post("/account-report")
async def generate_account_report(req: AccountReportRequest, db: Session = Depends(get_db)):
    """Generate a Gemini AI risk report for a specific bank account."""
    from models import BankAccount, LiveAttackLog, LoginVerification

    account = db.query(BankAccount).filter(BankAccount.account_number == req.account_number).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Gather attack logs
    attacks = db.query(LiveAttackLog).filter(
        LiveAttackLog.target_account == req.account_number
    ).order_by(LiveAttackLog.timestamp.desc()).limit(20).all()

    # Gather login verifications
    verifications = db.query(LoginVerification).filter(
        LoginVerification.account_number == req.account_number
    ).order_by(LoginVerification.timestamp.desc()).limit(10).all()

    # Gather transactions (use user_id and receiver_id, not sender_account)
    txns = db.query(Transaction).filter(
        (Transaction.user_id == req.account_number) |
        (Transaction.receiver_id == req.account_number)
    ).order_by(Transaction.timestamp.desc()).limit(20).all()

    # Build context
    context_parts = [
        f"## Account Profile",
        f"- Holder: {account.holder_name}",
        f"- Account Number: {account.account_number}",
        f"- Balance: ₹{account.balance:,.2f}",
        f"- Phone: {account.phone}",
        f"- Email: {account.email}",
        f"- IFSC: {account.ifsc}",
        f"- Branch City: {account.city}",
        f"- Under Attack: {'YES' if account.is_under_attack else 'No'}",
        f"\n## Attack History ({len(attacks)} events)",
    ]

    for a in attacks:
        context_parts.append(f"- [{a.event_type}] IP: {a.attacker_ip} | Amount: ₹{a.amount or 0} | Status: {a.status} | {a.timestamp}")

    context_parts.append(f"\n## Login Verifications ({len(verifications)} records)")
    for v in verifications:
        context_parts.append(f"- Status: {v.status} | IP: {v.login_ip} | {v.timestamp}")

    context_parts.append(f"\n## Transaction History ({len(txns)} records)")
    for t in txns:
        context_parts.append(f"- {t.user_id} → {t.receiver_id or 'N/A'} | ₹{t.amount:,.2f} | {'FLAGGED' if t.is_flagged else 'OK'} | {t.timestamp}")

    context = "\n".join(context_parts)

    # Generate report with Gemini
    api_key = os.getenv("GOOGLE_API_KEY", "")
    report = ""

    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-2.0-flash")

            prompt = f"""You are an elite SOC-AML risk analyst at an Indian bank. Generate a comprehensive risk report for this bank account.

{context}

Provide your analysis in this structure:
## Account Risk Summary
Brief overview of the account holder and current risk status.

## Security Assessment
- Login pattern analysis
- Attack history review
- Vulnerability assessment

## Transaction Analysis
- Transaction patterns
- Suspicious activities if any
- Fund flow summary

## Risk Score & Recommendation
- Overall risk rating (LOW / MEDIUM / HIGH / CRITICAL)
- Recommended actions
- Compliance notes

Keep it concise but thorough. Use bullet points. Use Indian financial terminology (INR, UPI, IMPS, NEFT, RBI, FIU-IND)."""

            response = model.generate_content(prompt)
            report = response.text
            logger.info(f"Account report generated for {req.account_number}")
        except Exception as e:
            logger.warning(f"Gemini failed for account report: {e}")
            report = _generate_fallback_account_report(account, attacks, verifications, txns)
    else:
        report = _generate_fallback_account_report(account, attacks, verifications, txns)

    return {"report": report, "account_number": req.account_number}


def _generate_fallback_account_report(account, attacks, verifications, txns):
    """Local fallback when Gemini is unavailable."""
    risk = "CRITICAL" if account.is_under_attack else ("HIGH" if len(attacks) > 0 else "LOW")
    return f"""## Account Risk Summary
**{account.holder_name}** — A/C {account.account_number}
Balance: ₹{account.balance:,.2f} | Branch: {account.city} ({account.ifsc})
Current Status: {'⚠️ UNDER ACTIVE ATTACK' if account.is_under_attack else '✅ Secure'}

## Security Assessment
- Total login verifications: {len(verifications)}
- Attack events detected: {len(attacks)}
- {'Unauthorized access attempts detected — account may be compromised' if attacks else 'No unauthorized access detected'}

## Transaction Analysis
- Total transactions on record: {len(txns)}
- {'Suspicious transaction patterns require investigation' if account.is_under_attack else 'No suspicious patterns detected'}

## Risk Score: {risk}
- {'Immediate action required — freeze account and investigate' if risk == 'CRITICAL' else 'Standard monitoring recommended'}
- Report to FIU-IND if suspicious activity confirmed

*Generated locally — AI-enhanced analysis available when Gemini service is connected.*"""

