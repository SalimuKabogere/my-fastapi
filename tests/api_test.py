from fastapi.testclient import TestClient
from backend.main import app, sanitize_input
from backend.utils.sanitization import sanitize_username, validate_password, sanitize_free_text, sanitize_url

client = TestClient(app)

def test_register_and_login():
    # Register user
    response = client.post("/register", json={
        "username": "testuser",
        "password": "Password1!",
        "role": "user"
    })
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["username"] == "testuser"
    assert data["role"] == "user"

    # Login (use form data, not JSON)
    response = client.post("/login", data={
        "username": "testuser",
        "password": "Password1!",
        "role": "user"
    })
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["access_token"] is not None
    assert data["token_type"] == "bearer"


def test_get_all_users():
    # Register and login as admin
    client.post("/register", json={
        "username": "adminuser",
        "password": "Password1!",
        "role": "admin"
    })
    login = client.post("/login", data={
        "username": "adminuser",
        "password": "Password1!",
        "role": "admin"
    })
    token = login.json()["access_token"]
    # Get all users
    response = client.get("/users/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    users = response.json()
    assert any(u["username"] == "adminuser" for u in users)


def test_get_user_by_id():
    # Register and login
    reg = client.post("/register", json={
        "username": "bob",
        "password": "Password1!",
        "role": "user"
    })
    user_id = reg.json()["user_id"]
    login = client.post("/login", data={
        "username": "bob",
        "password": "Password1!",
        "role": "user"
    })
    token = login.json()["access_token"]
    # Get user by ID
    response = client.get(f"/users/{user_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["username"] == "bob"


def test_delete_user_as_admin():
    # Register admin and another user
    client.post("/register", json={
        "username": "admin2",
        "password": "Password1!",
        "role": "admin"
    })
    reg = client.post("/register", json={
        "username": "victim",
        "password": "Password1!",
        "role": "user"
    })
    victim_id = reg.json()["user_id"]
    login = client.post("/login", data={
        "username": "admin2",
        "password": "Password1!",
        "role": "admin"
    })
    token = login.json()["access_token"]
    # Delete user as admin
    response = client.delete(f"/users_del/{victim_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    assert response.json()["message"] == "User deleted successfully"


def test_delete_user_as_non_admin():
    # Register two users
    client.post("/register", json={
        "username": "user1",
        "password": "Password1!",
        "role": "user"
    })
    reg = client.post("/register", json={
        "username": "user2",
        "password": "Password1!",
        "role": "user"
    })
    user2_id = reg.json()["user_id"]
    login = client.post("/login", data={
        "username": "user1",
        "password": "Password1!",
        "role": "user"
    })
    token = login.json()["access_token"]
    # Try to delete as non-admin
    response = client.delete(f"/users_del/{user2_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403, response.text
    assert "Only admins can delete users" in response.text


def test_login_wrong_password():
    # Register user
    client.post("/register", json={
        "username": "wrongpassuser",
        "password": "rightpass",
        "role": "user"
    })
    # Try to login with wrong password
    response = client.post("/login", data={
        "username": "wrongpassuser",
        "password": "wrongpass",
        "role": "user"
    })
    assert response.status_code == 401, response.text
    assert "Invalid credentials" in response.text


def test_sanitize_input():
    # Script tag should be removed
    assert sanitize_input('<script>alert(1)</script>') == ''
    # HTML tags should be removed
    assert sanitize_input('<b>bold</b>') == 'bold'
    # URL-encoded script tag should be removed
    assert sanitize_input('%3Cscript%3Ealert(1)%3C%2Fscript%3E') == ''
    # Normal string should remain unchanged
    assert sanitize_input('normalUser') == 'normalUser'
    # URL with HTML tags should have tags removed
    assert sanitize_input('https://example.com/<b>test</b>') == 'https://example.com/test'
    # URL-encoded URL should be decoded and tags removed
    assert sanitize_input('https%3A%2F%2Fexample.com%2F%3Cb%3Etest%3C%2Fb%3E') == 'https://example.com/test'
    # URL with script tag should have script removed
    assert sanitize_input('https://evil.com/<script>alert(1)</script>') == 'https://evil.com/'
    # URL-encoded script in URL
    assert sanitize_input('https%3A%2F%2Fevil.com%2F%3Cscript%3Ealert(1)%3C%2Fscript%3E') == 'https://evil.com/'


def test_sanitize_username():
    assert sanitize_username('normalUser') == 'normalUser'
    assert sanitize_username('user_123-abc') == 'user_123-abc'
    assert sanitize_username('user!@#') == 'user'
    assert sanitize_username('user name') == 'username'
    assert sanitize_username('a'*40) == 'a'*32  # length limit
    # Unicode normalization
    assert sanitize_username('u\uFF21ser') == 'uAser'  # Fullwidth A


def test_validate_password():
    assert validate_password('Password1!')
    assert not validate_password('short1!')  # too short
    assert not validate_password('allletters!')  # no number
    assert not validate_password('12345678!')  # no letter
    assert not validate_password('Password1')  # no symbol
    assert not validate_password('')
    assert not validate_password('a'*129 + '1!')  # too long


def test_sanitize_free_text():
    assert sanitize_free_text('<b>hello</b>') == 'hello'
    assert sanitize_free_text('<script>alert(1)</script>hello') == 'hello'
    assert sanitize_free_text('normal text') == 'normal text'
    assert sanitize_free_text('a'*2000) == 'a'*1024  # length limit
    # Unicode normalization
    assert sanitize_free_text('ＡＢＣ') == 'ABC'


def test_sanitize_url():
    assert sanitize_url('https://example.com') == 'https://example.com'
    assert sanitize_url('https://example.com/<b>test</b>') == 'https://example.com/test'
    assert sanitize_url('https%3A%2F%2Fexample.com%2F%3Cb%3Etest%3C%2Fb%3E') == 'https://example.com/test'
    assert sanitize_url('ftp://files.example.com/file.txt') == 'ftp://files.example.com/file.txt'
    assert sanitize_url('not a url') == ''
    assert sanitize_url('https://evil.com/<script>alert(1)</script>') == 'https://evil.com/'
    assert sanitize_url('https%3A%2F%2Fevil.com%2F%3Cscript%3Ealert(1)%3C%2Fscript%3E') == 'https://evil.com/'


def test_register_invalid_username():
    response = client.post('/register', json={
        'username': 'bad!@#user',
        'password': 'Password1!',
        'role': 'user'
    })
    # Should succeed, but username will be sanitized to 'baduser'
    assert response.status_code == 200
    assert response.json()['username'] == 'baduser'


def test_register_invalid_password():
    response = client.post('/register', json={
        'username': 'validuser',
        'password': 'short',
        'role': 'user'
    })
    assert response.status_code == 400
    assert 'Password must be' in response.text


def test_register_invalid_role():
    response = client.post('/register', json={
        'username': 'validuser2',
        'password': 'Password1!',
        'role': '<b>admin</b>'
    })
    # Role will be sanitized to 'admin', which is valid
    assert response.status_code == 200
    assert response.json()['role'] == 'admin'
    # Now try an invalid role
    response = client.post('/register', json={
        'username': 'validuser3',
        'password': 'Password1!',
        'role': 'notarole'
    })
    assert response.status_code == 400
    assert 'Role must be' in response.text
