from app.models import AuditLog
from app import db
from flask import request
from datetime import datetime

def log_action(username, action, status, details=None):
    """Log an action to the audit trail"""
    try:
        audit_entry = AuditLog(
            username=username,
            action=action,
            status=status,
            ip_address=request.remote_addr if request else None,
            details=details,
            timestamp=datetime.utcnow()
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        print(f"Error logging action: {str(e)}")
        db.session.rollback()