#!/usr/bin/env python3
"""
Recon7 Password Recovery & Reset Utility
Usage:
    # Interactive mode:
    python scripts/reset_password.py

    # CLI argument mode:
    python scripts/reset_password.py --email admin@example.com --password NewSecurePass123!

    # Docker container execution:
    docker exec -it r7-app python scripts/reset_password.py --email admin@example.com

    # List all users:
    python scripts/reset_password.py --list
"""

import sys
import os
import getpass
import argparse

# Add repository root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.auth import hash_password, validate_password_complexity
from storage.db import get_db_session, get_user_by_email, list_iam_users, update_iam_user, init_db


def main():
    parser = argparse.ArgumentParser(description="Recon7 User Password Recovery Utility")
    parser.add_argument("-e", "--email", type=str, help="Email address of the user to reset")
    parser.add_argument("-p", "--password", type=str, help="New password for the user")
    parser.add_argument("-l", "--list", action="store_true", help="List all registered users and roles")
    args = parser.parse_args()

    init_db()

    with get_db_session() as db:
        if args.list:
            users = list_iam_users(db)
            if not users:
                print("[!] No users found in database.")
                return 0

            print("\nRegistered Recon7 Users:")
            print("-" * 65)
            print(f"{'Email':<30} {'Role':<15} {'Active':<8} {'Full Name'}")
            print("-" * 65)
            for u in users:
                status = "Yes" if u.is_active else "No"
                print(f"{u.email:<30} {u.role:<15} {status:<8} {u.full_name or 'N/A'}")
            print("-" * 65 + "\n")
            return 0

        target_email = args.email
        if not target_email:
            users = list_iam_users(db)
            if users:
                print("\nRegistered accounts:")
                for u in users:
                    print(f"  - {u.email} ({u.role})")
                print("")
            target_email = input("Enter user email address: ").strip()

        if not target_email:
            print("[ERROR] Email is required.")
            return 1

        user = get_user_by_email(db, target_email)
        if not user:
            print(f"[ERROR] No user found with email '{target_email}'.")
            return 1

        new_password = args.password
        if not new_password:
            new_password = getpass.getpass("Enter new password: ")
            confirm_pw = getpass.getpass("Confirm new password: ")
            if new_password != confirm_pw:
                print("[ERROR] Passwords do not match.")
                return 1

        try:
            validate_password_complexity(new_password)
            hashed_pw = hash_password(new_password)
        except ValueError as e:
            print(f"[ERROR] {str(e)}")
            return 1

        update_iam_user(db=db, user_id=user.id, password_hash=hashed_pw, is_active=True)
        print(f"\n[SUCCESS] Password for user '{user.email}' ({user.role}) has been reset successfully.")
        print("[*] You can now sign in at http://localhost:8000 (or http://localhost:8080).\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
