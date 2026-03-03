"""
SQLAlchemy ORM Models — Transaction, CyberLog, AiCache
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text

from database import Base


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tx_id = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(String(30), nullable=False, index=True)
    user_name = Column(String(100), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(5), default="INR")
    transfer_method = Column(String(20), nullable=False)  # UPI, IMPS, NEFT
    upi_id = Column(String(80), nullable=True)
    receiver_id = Column(String(30), nullable=True, index=True)
    receiver_name = Column(String(100), nullable=True)
    ip_address = Column(String(50), nullable=True, index=True)
    city = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_flagged = Column(Boolean, default=False, index=True)
    flag_reason = Column(String(200), nullable=True)


class CyberLog(Base):
    __tablename__ = "cyber_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(String(30), nullable=False, index=True)
    user_name = Column(String(100), nullable=False)
    event_type = Column(String(50), nullable=False)  # e.g. aadhaar_phishing, fake_kyc_sms
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    ip_address = Column(String(50), nullable=True, index=True)
    city = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AiCache(Base):
    __tablename__ = "ai_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_hash = Column(String(64), unique=True, nullable=False, index=True)
    threat_narrative = Column(Text, nullable=False)
    threat_context = Column(Text, nullable=True)  # JSON of input params
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FrozenAccount(Base):
    __tablename__ = "frozen_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_id = Column(String(30), unique=True, nullable=False, index=True)
    frozen_by = Column(String(100), default="SOC-AML Automated Framework")
    frozen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    reason = Column(String(200), nullable=True)


class SandboxSession(Base):
    """Mirror Sandbox — each row = one trapped attacker session."""
    __tablename__ = "sandbox_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(50), unique=True, nullable=False, index=True)
    attacker_name = Column(String(100), nullable=False)
    attacker_phone = Column(String(20), nullable=True)
    attacker_ip = Column(String(50), nullable=False)
    risk_factor = Column(Float, nullable=False)  # ≥ 0.90 triggered sandbox
    city = Column(String(50), nullable=True)
    state = Column(String(50), default="Tamil Nadu")
    duration_minutes = Column(Integer, default=0)
    status = Column(String(30), default="TRAPPED")  # TRAPPED | RELEASED | FLAGGED
    entry_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tools_detected = Column(Text, nullable=True)  # JSON list of tools/techniques


class SandboxTransaction(Base):
    """Fake transfers attempted by a trapped attacker inside the sandbox."""
    __tablename__ = "sandbox_transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(50), nullable=False, index=True)
    tx_id = Column(String(50), unique=True, nullable=False)
    mule_account_number = Column(String(20), nullable=False)
    mule_bank_name = Column(String(100), nullable=True)
    mule_ifsc = Column(String(15), nullable=True)
    receiver_name = Column(String(100), nullable=False)
    receiver_phone = Column(String(20), nullable=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(5), default="INR")
    transfer_method = Column(String(20), nullable=False)
    city = Column(String(50), nullable=True)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    status = Column(String(30), default="INTERCEPTED")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BankAccount(Base):
    """Fake bank accounts for the live attack simulation portal."""
    __tablename__ = "bank_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_number = Column(String(20), unique=True, nullable=False, index=True)
    holder_name = Column(String(100), nullable=False)
    phone = Column(String(20), nullable=True)
    email = Column(String(100), nullable=True)
    login_username = Column(String(50), unique=True, nullable=False)
    login_password = Column(String(100), nullable=False)  # plain-text for demo only
    balance = Column(Float, default=1000000.0)
    ifsc = Column(String(15), default="DEMO0001234")
    city = Column(String(50), default="Chennai")
    is_under_attack = Column(Boolean, default=False)


class LiveAttackLog(Base):
    """Real-time log of every action from the fake bank portal."""
    __tablename__ = "live_attack_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), unique=True, nullable=False, index=True)
    event_type = Column(String(30), nullable=False)  # LOGIN_ATTEMPT, LOGIN_SUCCESS, TRANSFER_ATTEMPT, BALANCE_CHECK
    attacker_ip = Column(String(50), nullable=False)
    user_agent = Column(Text, nullable=True)
    target_account = Column(String(20), nullable=True)
    target_holder = Column(String(100), nullable=True)
    destination_account = Column(String(20), nullable=True)
    destination_name = Column(String(100), nullable=True)
    amount = Column(Float, nullable=True)
    transfer_method = Column(String(20), nullable=True)
    risk_score = Column(Float, default=0.95)
    status = Column(String(30), default="INTERCEPTED")  # INTERCEPTED, BLOCKED, SANDBOX_REDIRECT
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class LoginVerification(Base):
    """Login verification requests — real user approves/rejects remote logins."""
    __tablename__ = "login_verifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(50), unique=True, nullable=False, index=True)
    account_number = Column(String(20), nullable=False, index=True)
    holder_name = Column(String(100), nullable=True)
    login_ip = Column(String(50), nullable=False)
    user_agent = Column(Text, nullable=True)
    status = Column(String(20), default="PENDING")  # PENDING, APPROVED, REJECTED
    responded_at = Column(DateTime, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
