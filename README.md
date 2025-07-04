# FastAPI In-Memory User Management API

## Overview
This project is a FastAPI-based RESTful API for user management, using an **in-memory database** (Python dictionaries) for storing users. It supports user registration, login (with JWT authentication), and user management endpoints. All data is lost when the server restarts.

## Features
- Register new users (single or batch)
- Login and receive JWT tokens
- Get all users (admin or user role)
- Get user by ID
- Delete user (admin only)
- List all users (admin only)
- In-memory storage (no persistent database)

## Requirements
- Python 3.8+
- FastAPI
- Uvicorn
- passlib[bcrypt]
- python-jose
- python-dotenv


## API Usage

### 1. Register a User
- **Endpoint:** `POST /register`
- **Body:**
  ```json
  {
    "username": "alice",
    "password": "password123",
    "role": "admin"
  }
  ```
- **Response:** User info (without password)


### 3. Login
- **Endpoint:** `POST /login`
- **Body (form):**
  - `username=alice&password=password123`
- **Response:**
  ```json
  {
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer"
  }
  ```

### 4. Get All Users
- **Endpoint:** `GET /users/`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:** List of users

### 5. Get User by ID
- **Endpoint:** `GET /users/{user_id}`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:** User info

### 6. Delete User (Admin Only)
- **Endpoint:** `DELETE /users_del/{user_id}`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>` (must be admin)
- **Response:** Success message



## Authentication
- All endpoints except `/register` require a valid JWT token.
- Obtain a token via `/login` and include it in the `Authorization` header:
  ```
  Authorization: Bearer <JWT_TOKEN>
  ```

## Notes
- **In-memory storage:** All users are lost when the server restarts.
- **Roles:** Only users with role `admin` can delete users
- **Password security:** Passwords are hashed using bcrypt.

## Example Workflow
1. Register a user via `/register`
2. Login via `/login` to get a JWT token.
3. Use the token to access protected endpoints.
 