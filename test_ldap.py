from ldap3 import Server, Connection, ALL
import sys

print("=" * 70)
print("TESTING LDAP CONNECTION TO ACTIVE DIRECTORY")
print("=" * 70)

# Configuration
LDAP_SERVER = '192.168.1.100'  # no ldap:// prefix needed
LDAP_PORT = 389
LDAP_USE_SSL = False
LDAP_BIND_DN = 'cn=Administrator,cn=Users,DC=cnpslocal,DC=local'
LDAP_BIND_PASSWORD = 'CNPS@Admin123'  # Your admin password
LDAP_BASE_DN = 'DC=cnpslocal,DC=local'

print(f"\n[CONFIG]")
print(f"  Server: {LDAP_SERVER}:{LDAP_PORT}")
print(f"  Admin DN: {LDAP_BIND_DN}")
print(f"  Base DN: {LDAP_BASE_DN}")
print()

# Test 1: Connect to server
try:
    print("[1/4] Connecting to LDAP server...")
    server = Server(LDAP_SERVER, port=LDAP_PORT, use_ssl=LDAP_USE_SSL, get_info=ALL)
    print("  ✓ Server object created")
except Exception as e:
    print(f"  ✗ Failed: {e}")
    sys.exit(1)

# Test 2: Admin bind
try:
    print("\n[2/4] Binding as administrator...")
    conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, raise_exceptions=False)
    if conn.bind():
        print(f"  ✓ Admin bind successful")
    else:
        print(f"  ✗ Admin bind failed: {conn.last_error}")
        sys.exit(1)
except Exception as e:
    print(f"  ✗ Exception: {e}")
    sys.exit(1)

# Test 3: Search for users
try:
    print("\n[3/4] Searching for all users...")
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter='(objectClass=user)',
        attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf']
    )
    print(f"  ✓ Found {len(conn.entries)} users\n")

    # Show first 10 users
    for i, entry in enumerate(conn.entries[:10]):
        if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName.value:
            username = entry.sAMAccountName.value
            display = entry.displayName.value if hasattr(entry, 'displayName') and entry.displayName.value else 'N/A'
            print(f"    {i+1}. {username} - {display}")

            # Show groups
            if hasattr(entry, 'memberOf') and entry.memberOf.values:
                groups = [str(g).split(',')[0] for g in entry.memberOf.values]
                print(f"       Groups: {', '.join(groups[:3])}")

except Exception as e:
    print(f"  ✗ Search failed: {e}")
    sys.exit(1)

# Test 4: Test user authentication
try:
    print("\n[4/4] Testing user authentication...")
    test_username = 'admin_user'
    test_password = 'AdminPassword123!'

    upn = f'{test_username}@cnpslocal.local'
    print(f"  Username: {test_username}")
    print(f"  UPN: {upn}")

    user_conn = Connection(server, user=upn, password=test_password, raise_exceptions=False)
    if user_conn.bind():
        print(f"  ✓ User authentication successful!")
    else:
        print(f"  ✗ User authentication failed: {user_conn.last_error}")
        print("\n  Tips for troubleshooting:")
        print("    1. Check VM is running")
        print("    2. Check VM IP is correct (ping 192.168.1.100)")
        print("    3. Check firewall isn't blocking LDAP (port 389)")
        print("    4. Check passwords are correct")
        print("    5. Try different DN formats if needed (CN vs UPN)")

except Exception as e:
    print(f"  ✗ Exception: {e}")

print("\n" + "=" * 70)
print("LDAP TEST COMPLETE")
print("=" * 70)