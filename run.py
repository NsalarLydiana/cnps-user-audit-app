from app import create_app, db
from app.models import User, Role, Permission
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Create default roles if they don't exist
        if not Role.query.first():
            roles = [
                Role(name='Admin', description='Administrator'),
                Role(name='Auditor', description='Audit Officer'),
                Role(name='Standard User', description='Regular User')
            ]
            db.session.add_all(roles)
            db.session.commit()
            print("✓ Default roles created")

    print("✓ Starting Flask application...")
    app.run(debug=True, host='0.0.0.0', port=5000)