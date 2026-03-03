"""
Mirror Sandbox Router — /api/v1/sandbox

Endpoints for the "Mirror Sandbox" honeypot system.
When Gemini Risk Factor ≥ 0.9, attackers are silently redirected
to a fake banking environment. This router exposes the logged intelligence.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import SandboxSession, SandboxTransaction

router = APIRouter(prefix="/api/v1/sandbox", tags=["Mirror Sandbox"])


@router.get("/sessions")
async def get_sandbox_sessions(db: Session = Depends(get_db)):
    """
    List all trapped attacker sessions with their attempted transactions.
    Each session includes the attacker profile and every fake transfer they tried.
    """
    sessions = (
        db.query(SandboxSession)
        .order_by(SandboxSession.entry_time.desc())
        .all()
    )

    results = []
    for s in sessions:
        # Get all transactions for this session
        txns = (
            db.query(SandboxTransaction)
            .filter(SandboxTransaction.session_id == s.session_id)
            .order_by(SandboxTransaction.timestamp)
            .all()
        )

        total_attempted = sum(t.amount for t in txns)

        results.append({
            "session_id": s.session_id,
            "attacker_name": s.attacker_name,
            "attacker_phone": s.attacker_phone,
            "attacker_ip": s.attacker_ip,
            "risk_factor": s.risk_factor,
            "city": s.city,
            "state": s.state,
            "duration_minutes": s.duration_minutes,
            "status": s.status,
            "entry_time": s.entry_time.isoformat() + "Z",
            "tools_detected": s.tools_detected,
            "total_attempted_amount": round(total_attempted, 2),
            "transaction_count": len(txns),
            "transactions": [
                {
                    "tx_id": t.tx_id,
                    "mule_account_number": t.mule_account_number,
                    "mule_bank_name": t.mule_bank_name,
                    "mule_ifsc": t.mule_ifsc,
                    "receiver_name": t.receiver_name,
                    "receiver_phone": t.receiver_phone,
                    "amount": t.amount,
                    "currency": t.currency,
                    "transfer_method": t.transfer_method,
                    "city": t.city,
                    "lat": t.lat,
                    "lon": t.lon,
                    "status": t.status,
                    "timestamp": t.timestamp.isoformat() + "Z",
                }
                for t in txns
            ],
        })

    return results


@router.get("/mule-accounts")
async def get_mule_accounts(db: Session = Depends(get_db)):
    """
    List unique mule destination accounts with Tamil Nadu locations.
    Used by the Mule Account Map component.
    """
    txns = (
        db.query(SandboxTransaction)
        .order_by(SandboxTransaction.timestamp.desc())
        .all()
    )

    # De-duplicate by mule account number, keep richest data
    account_map: dict[str, dict] = {}
    for t in txns:
        key = t.mule_account_number
        if key not in account_map:
            # Look up the session for attacker info
            session = (
                db.query(SandboxSession)
                .filter(SandboxSession.session_id == t.session_id)
                .first()
            )
            account_map[key] = {
                "mule_account_number": t.mule_account_number,
                "mule_bank_name": t.mule_bank_name,
                "mule_ifsc": t.mule_ifsc,
                "receiver_name": t.receiver_name,
                "receiver_phone": t.receiver_phone,
                "city": t.city,
                "lat": t.lat,
                "lon": t.lon,
                "total_amount": 0,
                "attempt_count": 0,
                "attacker_name": session.attacker_name if session else "Unknown",
                "attacker_ip": session.attacker_ip if session else "Unknown",
                "status": t.status,
            }
        account_map[key]["total_amount"] += t.amount
        account_map[key]["attempt_count"] += 1

    # Round amounts
    for v in account_map.values():
        v["total_amount"] = round(v["total_amount"], 2)

    return list(account_map.values())
