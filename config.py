import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
    
    # Use PostgreSQL with new password
    SQLALCHEMY_DATABASE_URI = 'postgresql://cnps_admin:cnps_admin_password@localhost:5432/cnps_audit_db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Active Directory Configuration (VirtualBox VM)
    LDAP_SERVER = os.getenv('LDAP_SERVER', 'ldap://192.168.1.100')
    LDAP_PORT = int(os.getenv('LDAP_PORT', 389))
    LDAP_USE_SSL = os.getenv('LDAP_USE_SSL', 'False') == 'True'
    LDAP_BIND_DN = os.getenv('LDAP_BIND_DN', 'cn=Administrator,cn=Users,DC=cnpslocal,DC=local')
    LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD', '')
    LDAP_BASE_DN = os.getenv('LDAP_BASE_DN', 'DC=cnpslocal,DC=local')
    
    # 2FA Configuration
    TOTP_ISSUER_NAME = 'CNPS Cameroon UAC'