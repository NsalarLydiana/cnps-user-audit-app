import pyotp

class TOTPManager:
    """Manages Time-Based One-Time Password (2FA)"""
    
    @staticmethod
    def generate_secret():
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(username, secret):
        """Generate the provisioning URI"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name='CNPS Cameroon UAC'
        )
    
    @staticmethod
    def verify_token(secret, token):
        """Verify a TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except:
            return False