from app import create_app, db
from app.models import Role, Permission

app = create_app()

with app.app_context():
    # Create tables (safe to call multiple times)
    db.create_all()

    # -------------------
    # Helper functions
    # -------------------
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

    # -------------------
    # Roles
    # -------------------
    admin_role = get_or_create_role(
        'Admin', 'Administrator with full access'
    )
    auditor_role = get_or_create_role(
        'Auditor', 'Can view audit logs and reports'
    )
    user_role = get_or_create_role(
        'Standard User', 'Regular user with basic access'
    )

    # -------------------
    # Permissions
    # -------------------
    view_dashboard = get_or_create_permission(
        'view_dashboard', 'Access dashboard'
    )
    view_audit_logs = get_or_create_permission(
        'view_audit_logs', 'View audit logs'
    )
    manage_users = get_or_create_permission(
        'manage_users', 'Create/edit/delete users'
    )
    manage_roles = get_or_create_permission(
        'manage_roles', 'Manage roles and permissions'
    )
    export_data = get_or_create_permission(
        'export_data', 'Export audit data'
    )

    all_permissions = [
        view_dashboard,
        view_audit_logs,
        manage_users,
        manage_roles,
        export_data,
    ]

    # -------------------
    # Assign permissions
    # -------------------
    admin_role.permissions = all_permissions
    auditor_role.permissions = [
        view_dashboard,
        view_audit_logs,
    ]
    user_role.permissions = [
        view_dashboard,
    ]

    db.session.commit()
    print("Database seeded successfully (safe to re-run).")