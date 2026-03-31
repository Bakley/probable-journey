"""
═══════════════════════════════════════════════════════════════════
SOLID → S (Single Responsibility)
  One job: shape every HTTP response into the same envelope.
  Nothing else lives here.
═══════════════════════════════════════════════════════════════════
"""

from flask import jsonify


def success(data: dict | list = None, message: str = "", status: int = 200):
    """
    Standard success response.

    Shape:
    {
      "ok": true,
      "status": 200,
      "message": "...",
      "data": { ... }
    }
    """
    body = {"ok": True, "status": status, "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), status


def error(message: str, status: int = 400, details: list = None):
    """
    Standard error response.

    Shape:
    {
      "ok": false,
      "status": 400,
      "message": "...",
      "details": ["field error 1", "field error 2"]   ← optional
    }
    """
    body = {"ok": False, "status": status, "message": message}
    if details:
        body["details"] = details
    return jsonify(body), status
