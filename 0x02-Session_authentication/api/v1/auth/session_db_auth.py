#!/usr/bin/env python3
"""SessionDB auth ."""
from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """SessionDB auth ."""

    def create_session(self, user_id=None):
        """Override Create Session."""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        data = {
            "user_id": user_id,
            "session_id": session_id
        }
        user = UserSession(**data)
        user.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Override user from session ID."""
        user_id = UserSession.search({"session_id": session_id})
        if user_id:
            return user_id
        return None

    def destroy_session(self, request=None):
        """Del session."""
        if not request:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        user_session = UserSession.search({"session_id": session_id})
        if user_session:
            user_session[0].remove()
            return True
        return False
