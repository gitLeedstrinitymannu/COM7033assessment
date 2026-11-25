"""Create a staff or admin account. These roles cannot self-register (prevents privilege escalation).

Usage:  python create_user.py --role admin
"""
import argparse
import getpass
import sqlite3
import sys

import database as db
import security


def create_account(role, name, email, password):
    if role not in ("staff", "admin"):
        raise ValueError("Role must be 'staff' or 'admin'.")
    problems = security.password_problems(password)
    if problems:
        raise ValueError("Password needs: " + ", ".join(problems) + ".")
    db.init_sqlite()
    try:
        db.create_user(name.strip(), email.strip().lower(), security.hash_password(password), role=role)
    except sqlite3.IntegrityError:
        raise ValueError("An account with that email already exists.")
    return f"Created {role} account for {email.strip().lower()}."


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a staff or admin account.")
    parser.add_argument("--role", choices=["staff", "admin"], required=True)
    args = parser.parse_args()
    name = input("Full name: ")
    email = input("Email: ")
    password = getpass.getpass("Password (hidden): ")
    if password != getpass.getpass("Confirm password: "):
        sys.exit("Passwords do not match.")
    try:
        print(create_account(args.role, name, email, password))
    except ValueError as error:
        sys.exit(str(error))
