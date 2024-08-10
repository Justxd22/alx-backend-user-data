#!/usr/bin/env python3
"""SessionAuth class."""
from .auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """Session Authorization."""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates Session ID for user."""
        if not user_id or type(user_id) != str:
            return None
        idd = uuid4()
        self.user_id_by_session_id[str(idd)] = user_id
        return str(idd)

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns user ID from session ID."""
        if not session_id or type(session_id) != str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Return user instance from cookie value."""
        cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Delete session."""
        if not request:
            return False
        session_cookie = self.session_cookie(request)
        if not session_cookie:
            return False
        user_id = self.user_id_for_session_id(session_cookie)
        if not user_id:
            return False
        del self.user_id_by_session_id[session_cookie]
        return True
