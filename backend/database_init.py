#!/usr/bin/env python3
"""
Database initialization script for the user management system.
This script creates all tables and optionally seeds initial data.
"""

import asyncio
from sqlalchemy.orm import Session
from backend.models.database import engine, SessionLocal, Base
from backend.models.user import User, Role, Permission, UserRole, RolePermission, UserProfile
from backend.utils.authentication import hash_password
import uuid
from datetime import datetime

def create_tables():
    """Create all database tables."""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ Tables created successfully")

def seed_initial_data():
    """Seed the database with initial roles, permissions, and admin user."""
    db = SessionLocal()
    try:
        print("Seeding initial data...")
        
        # Create basic roles
        admin_role = Role(
            name="admin",
            description="Full system administrator with all permissions",
            is_active=True
        )
        user_role = Role(
            name="user",
            description="Standard user with basic permissions",
            is_active=True
        )
        
        db.add(admin_role)
        db.add(user_role)
        db.flush()  # Get the IDs
        
        # Create basic permissions
        permissions_data = [
            ("user.create", "user", "create", "Create new users"),
            ("user.read", "user", "read", "View user information"),
            ("user.update", "user", "update", "Update user information"),
            ("user.delete", "user", "delete", "Delete users"),
            ("user.list", "user", "list", "List all users"),
            ("role.create", "role", "create", "Create new roles"),
            ("role.read", "role", "read", "View role information"),
            ("role.update", "role", "update", "Update role information"),
            ("role.delete", "role", "delete", "Delete roles"),
            ("role.list", "role", "list", "List all roles"),
            ("permission.list", "permission", "list", "List all permissions"),
            ("audit.read", "audit", "read", "View audit logs"),
            ("session.manage", "session", "manage", "Manage user sessions"),
            ("profile.read", "profile", "read", "View user profiles"),
            ("profile.update", "profile", "update", "Update user profiles"),
        ]
        
        permissions = []
        for name, resource, action, description in permissions_data:
            permission = Permission(
                name=name,
                resource=resource,
                action=action,
                description=description
            )
            permissions.append(permission)
            db.add(permission)
        
        db.flush()  # Get permission IDs
        
        # Assign all permissions to admin role
        for permission in permissions:
            role_permission = RolePermission(
                role_id=admin_role.id,
                permission_id=permission.id
            )
            db.add(role_permission)
        
        # Assign basic permissions to user role
        user_permissions = ["user.read", "profile.read", "profile.update"]
        for perm_name in user_permissions:
            permission = next(p for p in permissions if p.name == perm_name)
            role_permission = RolePermission(
                role_id=user_role.id,
                permission_id=permission.id
            )
            db.add(role_permission)
        
        # Create default admin user
        admin_user = User(
            username="admin",
            email="admin@example.com",
            password_hash=hash_password("admin123!"),
            first_name="System",
            last_name="Administrator",
            is_active=True,
            is_verified=True
        )
        db.add(admin_user)
        db.flush()
        
        # Assign admin role to admin user
        user_admin_role = UserRole(
            user_id=admin_user.id,
            role_id=admin_role.id,
            assigned_by=admin_user.id  # Self-assigned
        )
        db.add(user_admin_role)
        
        # Create admin user profile
        admin_profile = UserProfile(
            user_id=admin_user.id,
            bio="System administrator account",
            timezone="UTC",
            language="en",
            theme="light",
            notifications_enabled=True
        )
        db.add(admin_profile)
        
        # Create a sample regular user
        regular_user = User(
            username="testuser",
            email="user@example.com",
            password_hash=hash_password("user123!"),
            first_name="Test",
            last_name="User",
            is_active=True,
            is_verified=True,
            created_by=admin_user.id
        )
        db.add(regular_user)
        db.flush()
        
        # Assign user role to regular user
        user_user_role = UserRole(
            user_id=regular_user.id,
            role_id=user_role.id,
            assigned_by=admin_user.id
        )
        db.add(user_user_role)
        
        # Create regular user profile
        user_profile = UserProfile(
            user_id=regular_user.id,
            bio="Test user account",
            timezone="UTC",
            language="en",
            theme="light"
        )
        db.add(user_profile)
        
        db.commit()
        print("✓ Initial data seeded successfully")
        print(f"✓ Admin user created: admin / admin123!")
        print(f"✓ Test user created: testuser / user123!")
        
    except Exception as e:
        db.rollback()
        print(f"✗ Error seeding data: {e}")
        raise
    finally:
        db.close()

def check_existing_data():
    """Check if database already has data."""
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        role_count = db.query(Role).count()
        return user_count > 0 or role_count > 0
    finally:
        db.close()

def reset_database():
    """Drop all tables and recreate them."""
    print("Resetting database...")
    Base.metadata.drop_all(bind=engine)
    print("✓ Tables dropped")
    create_tables()

def main():
    """Main initialization function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database initialization script")
    parser.add_argument("--reset", action="store_true", help="Reset database (drop and recreate all tables)")
    parser.add_argument("--seed", action="store_true", help="Seed initial data")
    parser.add_argument("--force", action="store_true", help="Force seed even if data exists")
    
    args = parser.parse_args()
    
    try:
        if args.reset:
            reset_database()
        else:
            create_tables()
        
        if args.seed:
            if not args.force and check_existing_data():
                print("Database already contains data. Use --force to override.")
                return
            seed_initial_data()
        
        print("✓ Database initialization completed successfully")
        
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        raise

if __name__ == "__main__":
    main()
