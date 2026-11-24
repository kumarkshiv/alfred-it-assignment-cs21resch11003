"""One JSON error shape for the whole API: {"error": code, "message": text}."""
from flask import jsonify


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def error_response(status: int, code: str, message: str, headers: dict | None = None):
    response = jsonify({"error": code, "message": message})
    response.status_code = status
    for key, value in (headers or {}).items():
        response.headers[key] = value
    return response
