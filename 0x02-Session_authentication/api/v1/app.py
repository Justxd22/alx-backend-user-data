#!/usr/bin/env python3
"""Route module for the API."""
from os import getenv
from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = 0
authT = os.getenv("AUTH_TYPE", 'auth')
a = {
    "auth": Auth,
    "basic_auth": BasicAuth,
    "session_auth": SessionAuth,
    "session_exp_auth": SessionExpAuth,
    "session_db_auth": SessionDBAuth,
}
try:
    auth = a[authT]()
except Exception:
    auth = BasicAuth()


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized handler."""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Forbidden handler."""
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler."""
    return jsonify({"error": "Not found"}), 404


@app.before_request
def authenticate_user():
    """Authenticate a user before processing a request."""
    if auth:
        setattr(request, "current_user", auth.current_user(request))
        null = [
            '/api/v1/status/',
            '/api/v1/unauthorized/',
            '/api/v1/forbidden/',
            '/api/v1/auth_session/login/',
        ]
        if auth.require_auth(request.path, null):
            if not auth.authorization_header(request) and \
                  not auth.session_cookie(request):
                abort(401)
            if auth.current_user(request) is None:
                abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
