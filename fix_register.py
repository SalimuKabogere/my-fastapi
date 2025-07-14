#!/usr/bin/env python3
"""Quick fix for the register endpoint syntax error."""

# Read the file
with open('backend/main.py', 'r') as f:
    content = f.read()

# Fix the broken register response syntax
content = content.replace(
    """    response = {
        user_id=user_id,
        username=sanitized_username,
        role=sanitized_role
    )""",
    """    response = {
        "user_id": str(user_id),
        "username": sanitized_username,
        "role": sanitized_role,
        "message": "User registered successfully"
    }"""
)

# Write back
with open('backend/main.py', 'w') as f:
    f.write(content)

print("Fixed register endpoint syntax")
