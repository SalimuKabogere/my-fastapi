#!/usr/bin/env python3
"""Simple database initialization for development."""

from backend.database_init import create_tables, seed_initial_data, reset_database

try:
    print("Initializing database...")
    reset_database()
    seed_initial_data()
    print("Database initialization completed!")
except Exception as e:
    print(f"Error: {e}")
