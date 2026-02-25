from ldap3 import Server, Connection, ALL

print("Testing LDAP connection to Active Directory on VirtualBox...")
print()

# Connect to VM's Active Directory
server = Server('ldap://192.168.1.100', port=389, use_ssl=False, get_info=ALL)

try:
    # Test admin bind
    conn = Connection(
        server,
        user='cn=Administrator,cn=Users,DC=cnpslocal,DC=local',
        password='CNPS@Admin123',  # Windows Server admin password
        auto_bind=True
    )
    
    print("✓ Successfully connected to Active Directory!")
    print()
    
    # Search for users
    conn.search(
        search_base='DC=cnpslocal,DC=local',
        search_filter='(objectClass=user)',
        attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf']
    )
    
    print(f"✓ Found {len(conn.entries)} users in Active Directory:\n")
    for entry in conn.entries:
        if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName.value:
            username = entry.sAMAccountName.value
            display_name = entry.displayName.value if hasattr(entry, 'displayName') and entry.displayName.value else 'N/A'
            print(f"  Username: {username}")
            print(f"  Display Name: {display_name}")
            if hasattr(entry, 'memberOf') and entry.memberOf.value:
                groups = ', '.join([str(g) for g in entry.memberOf.value])
                print(f"  Groups: {groups}")
            print()
    
    # Test user login
    print("\nTesting user login...")
    user_conn = Connection(
        server,
        user='cn=admin_user,ou=CNPS_Users,dc=cnpslocal,dc=local',
        password='AdminPassword123!',
        auto_bind=True
    )
    print("✓ admin_user login successful!")
    
except Exception as e:
    print(f"✗ Error connecting to Active Directory:")
    print(f"  {str(e)}")
    print()
    print("Troubleshooting:")
    print("  1. Check VM is running")
    print("  2. Check VM IP is 192.168.1.100 (ping from host: ping 192.168.1.100)")
    print("  3. Check firewall isn't blocking LDAP (port 389)")
    print("  4. Check passwords are correct")