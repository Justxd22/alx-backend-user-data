#!/usr/bin/env python3
"""Encrypting Passwords."""


import bcrypt


def hash_password(password: str) -> bytes:
    """Encrypting Passwords."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Isit valid?."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
