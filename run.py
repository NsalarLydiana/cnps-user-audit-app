from app import create_app, db
from app.models import User, Role, Permission

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Create default roles if they don't exist
        if not Role.query.first():
            admin_role = Role(name='Admin', description='Administrator')
            auditor_role = Role(name='Auditor', description='Audit Officer')
            user_role = Role(name='Standard User', description='Regular User')
            
            db.session.add(admin_role)
            db.session.add(auditor_role)
            db.session.add(user_role)
            db.session.commit()
            
            print("✓ Default roles created")
    
    print("✓ Starting Flask application...")
    app.run(debug=True, host='0.0.0.0', port=5000)