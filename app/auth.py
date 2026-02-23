from ldap3 import Server, Connection, ALL
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class ADAuthenticator:
    """Authenticates users against Windows Active Directory via LDAP"""
    
    def __init__(self):
        self.server = Server(
            current_app.config['LDAP_SERVER'],
            port=current_app.config['LDAP_PORT'],
            use_ssl=current_app.config['LDAP_USE_SSL'],
            get_info=ALL
        )
    
    def authenticate(self, username, password):
        """Authenticate user against Active Directory"""
        try:
            upn = f"{username}@cnpslocal.local"
            conn = Connection(self.server, user=upn, password=password)
            
            if conn.bind():
                logger.info(f"AD authentication successful for user: {username}")
                return True, {"username": username, "upn": upn}
            else:
                logger.warning(f"AD authentication failed for user: {username}")
                return False, None
        
        except Exception as e:
            logger.error(f"AD authentication error: {str(e)}")
            return False, None
    
    def get_user_info(self, username):
        """Retrieve user information from Active Directory"""
        try:
            conn = Connection(
                self.server,
                user=current_app.config['LDAP_BIND_DN'],
                password=current_app.config['LDAP_BIND_PASSWORD']
            )
            
            if not conn.bind():
                logger.error("Failed to bind as admin")
                return None
            
            search_filter = f"(sAMAccountName={username})"
            conn.search(
                search_base=current_app.config['LDAP_BASE_DN'],
                search_filter=search_filter,
                attributes=['mail', 'displayName', 'memberOf', 'distinguishedName']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                groups = []
                if hasattr(entry, 'memberOf') and entry.memberOf.values:
                    groups = [str(g) for g in entry.memberOf.values]
                
                role = 'Standard User'
                if any('CNPS_Admins' in group for group in groups):
                    role = 'Admin'
                elif any('CNPS_Auditors' in group for group in groups):
                    role = 'Auditor'
                
                return {
                    'username': username,
                    'email': str(entry.mail.value) if hasattr(entry, 'mail') and entry.mail.value else f"{username}@cnpslocal.local",
                    'display_name': str(entry.displayName.value) if hasattr(entry, 'displayName') and entry.displayName.value else username,
                    'groups': groups,
                    'role': role
                }
            
            logger.warning(f"User not found in AD: {username}")
            return None
        
        except Exception as e:
            logger.error(f"Error retrieving user info: {str(e)}")
            return None