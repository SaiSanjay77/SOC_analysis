"""
seed_db.py — Initialize the database tables.

No mock data — all accounts are created via the Bank Server portal.

Usage:
    cd backend
    python seed_db.py
"""

from database import init_db


def seed():
    print("Initializing database tables...")
    init_db()
    print("✓ Database tables created successfully")
    print()
    print("No mock data seeded — create accounts via the Bank Server portal:")
    print("  Portal URL: http://YOUR-IP:8000/bankserver")
    print()


if __name__ == "__main__":
    seed()
