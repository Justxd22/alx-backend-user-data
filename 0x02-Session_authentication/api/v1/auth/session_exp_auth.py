#!/usr/bin/env python3
"""SessionExpAuth class."""
from .session_auth import SessionAuth
from datetime import datetime, timedelta
import os

class SessionExpAuth(SessionAuth):
    """SessionExp Authorization."""
    def __init__(self):
        """iniiit."""
        self.session_duration = int(os.getenv("SESSION_DURATION", 0))

    def create_session(self, user_id=None):
        """Override create session method."""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        sessionData = {
            "user_id": user_id,
            "created_at": datetime.now()
        }
        self.user_id_by_session_id[session_id] = sessionData
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Get user ID from session ID."""
        if not session_id:
            return None
        user_details = self.user_id_by_session_id.get(session_id)
        if not user_details:
            return None
        if "created_at" not in user_details.keys():
            return None
        if self.session_duration <= 0:
            return user_details.get("user_id")
        created_at = user_details.get("created_at")
        allowed_window = created_at + timedelta(seconds=self.session_duration)
        if allowed_window < datetime.now():
            return None
        return user_details.get("user_id")
