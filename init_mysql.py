#!/usr/bin/env python3
"""Initialize MySQL database with tables and sample data."""

import os
from backend.models.database import engine, SessionLocal
from backend.models.user import Base, User, Role, Permission, RolePermission, UserRole, UserProfile
from backend.utils.authentication import hash_password
from sqlalchemy import text

def create_database():
    """Create the database if it doesn't exist."""
    try:
        # Try to connect to MySQL server without database
        db_url = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost:3306/userdb")
        server_url = db_url.rsplit('/', 1)[0]  # Remove database name
        db_name = db_url.rsplit('/', 1)[1]     # Get database name
        
        from sqlalchemy import create_engine
        server_engine = create_engine(server_url)
        
        with server_engine.connect() as conn:
            # Create database if it doesn't exist
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {db_name}"))
            conn.commit()
            print(f"✅ Database '{db_name}' ready")
            
    except Exception as e:
        print(f"⚠️  Could not create database: {e}")
        print("Using existing connection...")

def init_database():
    """Initialize database with tables and sample data."""
    try:
        print("🗄️  Creating database tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Tables created successfully")
        
        db = SessionLocal()
        
        # Check if roles exist
        existing_roles = db.query(Role).count()
        if existing_roles > 0:
            print("✅ Database already has data")
            db.close()
            return
        
        print("📝 Seeding initial data...")
        
        # Create roles
        admin_role = Role(name="admin", description="Administrator role")
        user_role = Role(name="user", description="Standard user role")
        db.add(admin_role)
        db.add(user_role)
        db.flush()
        
        # Create permissions
        permissions = [
            ("user.create", "user", "create"),
            ("user.read", "user", "read"),
            ("user.update", "user", "update"),
            ("user.delete", "user", "delete"),
            ("user.list", "user", "list"),
        ]
        
        perm_objects = []
        for name, resource, action in permissions:
            perm = Permission(name=name, resource=resource, action=action)
            perm_objects.append(perm)
            db.add(perm)
        
        db.flush()
        
        # Assign all permissions to admin
        for perm in perm_objects:
            role_perm = RolePermission(role_id=admin_role.id, permission_id=perm.id)
            db.add(role_perm)
        
        # Assign basic permissions to user
        user_perms = ["user.read"]
        for perm_name in user_perms:
            perm = next(p for p in perm_objects if p.name == perm_name)
            role_perm = RolePermission(role_id=user_role.id, permission_id=perm.id)
            db.add(role_perm)
        
        # Create admin user
        admin_user = User(
            username="admin",
            email="admin@example.com",
            password_hash=hash_password("admin123!"),
            first_name="System",
            last_name="Admin",
            is_active=True,
            is_verified=True
        )
        db.add(admin_user)
        db.flush()
        
        # Assign admin role
        admin_user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
        db.add(admin_user_role)
        
        # Create admin profile
        admin_profile = UserProfile(
            user_id=admin_user.id,
            bio="System administrator",
            language="en",
            theme="light"
        )
        db.add(admin_profile)
        
        db.commit()
        print("✅ Sample data created:")
        print("   👤 Admin: admin / admin123!")
        
        db.close()
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        raise

if __name__ == "__main__":
    create_database()
    init_database()
    print("🎉 Database initialization complete!")
