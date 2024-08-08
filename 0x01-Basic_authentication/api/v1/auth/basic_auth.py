#!/usr/bin/env python3
"""."""
from .auth import Auth
from models.user import User
from typing import TypeVar, Tuple
import base64

class BasicAuth(Auth):
    """."""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """."""
        if not authorization_header:
            return None
        if type(authorization_header) != str:
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]
    

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """."""
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            return base64.b64decode(
                    base64_authorization_header,
                    validate=True,
            ).decode('utf-8')
        except:
            return None


    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """."""
        if not decoded_base64_authorization_header or \
            type(decoded_base64_authorization_header) != str or \
                ":" not in decoded_base64_authorization_header:
            return (None, None)
        x = decoded_base64_authorization_header.split(":")
        return (x[0], x[1])


    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """."""
        if not user_email or type(user_email) != str or \
            not user_pwd or type(user_pwd) != str:
            return None
        try:
            u = User.search({'email': user_email})
        except Exception:
                return None
        if len(u) <= 0:
            return None
        if u[0].is_valid_password(user_pwd):
            return u[0]
        

    def current_user(self, request=None) -> TypeVar('User'):
        """."""
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
