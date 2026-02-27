import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

    SQLALCHEMY_DATABASE_URI = (
        'postgresql://cnps_admin:cnps_admin_password@localhost:5432/cnps_audit_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

    SQLALCHEMY_DATABASE_URI = (
        'postgresql://cnps_admin:cnps_admin_password@localhost:5432/cnps_audit_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # LDAP Configuration - FIXED
    LDAP_SERVER = os.getenv('LDAP_SERVER', '192.168.1.100')  # ✓ NO ldap:// prefix
    LDAP_PORT = int(os.getenv('LDAP_PORT', 389))
    LDAP_USE_SSL = os.getenv('LDAP_USE_SSL', 'False') == 'True'
    LDAP_BIND_DN = os.getenv(
        'LDAP_BIND_DN',
        'cn=Administrator,cn=Users,DC=cnpslocal,DC=local'
    )
    LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD', 'CNPS@Admin123')  # ✓ Your actual admin password
    LDAP_BASE_DN = os.getenv(
        'LDAP_BASE_DN',
        'DC=cnpslocal,DC=local'  # ✓ Changed from OU=CNPS_Users to search entire domain
    )
    LDAP_USER_SEARCH_FILTER = os.getenv(
        'LDAP_USER_SEARCH_FILTER',
        '(sAMAccountName={username})'
    )

    TOTP_ISSUER_NAME = 'CNPS Cameroon UAC'
    LDAP_SERVER = os.getenv('LDAP_SERVER', 'ldap://192.168.1.100')
    LDAP_PORT = int(os.getenv('LDAP_PORT', 389))
    LDAP_USE_SSL = os.getenv('LDAP_USE_SSL', 'False') == 'True'
    LDAP_BIND_DN = os.getenv(
        'LDAP_BIND_DN',
        'cn=Administrator,cn=Users,DC=cnpslocal,DC=local'
    )
    LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD')
    LDAP_BASE_DN = os.getenv(
        'LDAP_BASE_DN',
        'OU=CNPS_Users,DC=cnpslocal,DC=local'
    )
    LDAP_USER_SEARCH_FILTER = os.getenv(
        'LDAP_USER_SEARCH_FILTER',
        '(sAMAccountName={username})'
    )

    TOTP_ISSUER_NAME = 'CNPS Cameroon UAC'