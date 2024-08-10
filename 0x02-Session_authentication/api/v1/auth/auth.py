#!/usr/bin/env python3
"""This module defines the `Auth` class which handles authorization logic.

for web requests, such as determining if a path requires authentication,
retrieving the authorization header, and identifying the current user.
"""

from flask import request
from typing import List, TypeVar
import os

class Auth:
    """
    A class used to represent an authorization system for web requests.

    Methods
    -------
    require_auth(path: str, excluded_paths: List[str]) -> bool
        Determines if the requested path requires authentication.

    authorization_header(request=None) -> str
        Retrieves the Authorization header from the given request.

    current_user(request=None) -> TypeVar('User')
        Retrieves the current user based on the request
        (placeholder implementation).
    """

    def __init__(self) -> None:
        """Initialize the Auth class."""
        pass

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if the requested path requires authentication.

        Parameters
        ----------
        path : str
            The path being accessed.
        excluded_paths : List[str]
            A list of paths that do not require authentication.

        Returns
        -------
        bool
            True if the path requires authentication, False otherwise.
        """
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
        """
        Retrieve the Authorization header from the given request.

        Parameters
        ----------
        request : Flask request object, optional
            The request object from which to retrieve the Authorization header.

        Returns
        -------
        str
            The value of the Authorization header, or None
            if it is not present.
        """
        if not request:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user based on the request.

        Note: This is a placeholder implementation and should be overridden.

        Parameters
        ----------
        request : Flask request object, optional
            The request object used to determine the current user.

        Returns
        -------
        TypeVar('User')
            The current user (None in this placeholder implementation).
        """
        return None

    def session_cookie(self, request=None):
        """Get cookie from request."""
        if not request:
            return None
        return request.cookies.get(os.getenv('SESSION_NAME', '_my_session_id'))
