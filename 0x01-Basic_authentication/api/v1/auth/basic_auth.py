#!/usr/bin/env python3
"""
This module defines the `BasicAuth` class, which extends the `Auth` class.

to provide basic HTTP authentication methods such as extracting and decoding
the authorization header, and retrieving user credentials.
"""

from .auth import Auth
from models.user import User
from typing import TypeVar, Tuple
import base64


class BasicAuth(Auth):
    """
    A class to handle Basic HTTP Authentication for web requests.

    Methods
    -------
    extract_base64_authorization_header(authorization_header: str) -> str
        Extracts the Base64 part of the Authorization header.

    decode_base64_authorization_header(base64_authorization_header: str) -> str
        Decodes the Base64 encoded Authorization header.

    extract_user_credentials(decoded_base64_authorization_header: str) ->
    Tuple[str, str]
        Extracts the user credentials (email and password) from the decoded
        Authorization header.

    user_object_from_credentials(user_email: str, user_pwd: str)
    -> TypeVar('User')
        Retrieves the user object from the credentials (email and password).

    current_user(request=None) -> TypeVar('User')
        Retrieves the current user from the request using basic authentication.
    """

    def extract_base64_authorization_header(self, authorization_header: str) \
            -> str:
        """
        Extract the Base64 part of the Authorization header.

        Parameters
        ----------
        authorization_header : str
            The full Authorization header.

        Returns
        -------
        str
            The Base64 encoded string, or None if the header
            is invalid or missing.
        """
        if not authorization_header:
            return None
        if type(authorization_header) != str:
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decode the Base64 encoded Authorization header.

        Parameters
        ----------
        base64_authorization_header : str
            The Base64 encoded string from the Authorization header.

        Returns
        -------
        str
            The decoded string (usually in the format 'user:password'),
            or None if decoding fails.
        """
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            return base64.b64decode(
                base64_authorization_header,
                validate=True,
            ).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> Tuple[str, str]:
        """
        Extract the user credentials (email and password) from the decoded.

        Authorization header.

        Parameters
        ----------
        decoded_base64_authorization_header : str
            The decoded string from the Base64 encoded Authorization header.

        Returns
        -------
        Tuple[str, str]
            A tuple containing the email and password, or (None, None)
            if the header is invalid.
        """
        if not decoded_base64_authorization_header or \
            type(decoded_base64_authorization_header) != str or \
                ":" not in decoded_base64_authorization_header:
            return (None, None)
        x = decoded_base64_authorization_header.split(":")
        return (x[0], x[1])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """
        Retrieve the user object from the credentials (email and password).

        Parameters
        ----------
        user_email : str
            The email of the user.
        user_pwd : str
            The password of the user.

        Returns
        -------
        TypeVar('User')
            The user object if found and credentials are valid,
            or None otherwise.
        """
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
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user from the request using basic authentication.

        Parameters
        ----------
        request : Flask request object, optional
            The request object containing the authorization header.

        Returns
        -------
        TypeVar('User')
            The user object if credentials are valid,
            or None if authentication fails.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
