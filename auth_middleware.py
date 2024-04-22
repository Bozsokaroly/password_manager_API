from functools import wraps
import jwt
from flask import request, abort, jsonify
from flask import current_app
import models
from flask_babel import Babel, gettext as _

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_token = None
        if "Authorization" in request.headers:
            auth_parts = request.headers["Authorization"].split()
            if len(auth_parts) == 2 and auth_parts[0] == "Bearer":
                auth_token = auth_parts[1]

        if not auth_token:
            return jsonify({
                "message": _("A token is required for access"),
                "data": None,
                "error": _("Unauthorized")
            }), 401

        try:
            payload = jwt.decode(auth_token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            authenticated_user = models.User().get_by_id(payload["user_id"])
            if authenticated_user is None:
                return jsonify({
                    "message": _("Token is not valid"),
                    "data": None,
                    "error": _("Unauthorized")
                }), 401
            if not authenticated_user["active"]:
                abort(403)
        except Exception as error:
            return jsonify({
                "message": _("An error occurred during token validation"),
                "data": None,
                "error": str(error)
            }), 500

        return f(authenticated_user, *args, **kwargs)

    return wrapper
