from app import create_app, db
from app.models import Role, Permission

app = create_app()

with app.app_context():
    # Create roles (ONLY if they don't exist)
    def get_or_create_role(name, description):
        role = Role.query.filter_by(name=name).first()
        if not role:
            role = Role(name=name, description=description)
            db.session.add(role)
            db.session.commit()
        return role

    def get_or_create_permission(name, description):
        perm = Permission.query.filter_by(name=name).first()
        if not perm:
            perm = Permission(name=name, description=description)
            db.session.add(perm)
            db.session.commit()
        return perm

    admin_role = get_or_create_role(
        'Admin', 'Administrator with full access'
    )
    auditor_role = get_or_create_role(
        'Auditor', 'Can view audit logs and reports'
    )
    user_role = get_or_create_role(
        'Standard User', 'Regular user with basic access'
    )

    permissions = [
        get_or_create_permission('view_dashboard', 'Access dashboard'),
        get_or_create_permission('view_audit_logs', 'View audit logs'),
        get_or_create_permission('manage_users', 'Create/edit/delete users'),
        get_or_create_permission('manage_roles', 'Manage roles and permissions'),
        get_or_create_permission('export_data', 'Export audit data'),
    ]

    admin_role.permissions = permissions
    auditor_role.permissions = [
        p for p in permissions
        if p.name in ['view_dashboard', 'view_audit_logs']
    ]
    user_role.permissions = [
        p for p in permissions
        if p.name == 'view_dashboard'
    ]

    db.session.commit()
    print("Roles and permissions created successfully!")
