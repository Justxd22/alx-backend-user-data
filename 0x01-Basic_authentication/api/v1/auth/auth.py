#!/usr/bin/env python3
"""."""
from flask import request
from typing import List, TypeVar


class Auth:
    """."""

    def __init__(self) -> None:
        """."""
        pass

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """."""
        if not path:
            return True
        if not excluded_paths:
            return True
        for x in excluded_paths:
            if "*" in x:
                ex = x.split("*")[0]
                if ex in path:
                    return False
            if path in x:
                return False
        return True


    def authorization_header(self, request=None) -> str:
        """."""
        if not request:
            return None
        return request.headers.get('Authorization', None)


    def current_user(self, request=None) -> TypeVar('User'):
        """."""
        return None
