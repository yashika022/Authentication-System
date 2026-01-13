import pytest
from app import app, users_db
import json

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def clear_db():
    users_db.clear()

def test_home(client):
    response = client.get('/')
    assert response.status_code == 200
    assert json.loads(response.data)['message'] == 'Auth System Running!'

def test_register_success(client):
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    response = client.post('/register', json=data)
    assert response.status_code == 200
    assert 'Registration successful' in json.loads(response.data)['message']
    assert 'test@example.com' in users_db

def test_register_weak_password(client):
    data = {'email': 'test@example.com', 'password': 'weak'}
    response = client.post('/register', json=data)
    assert response.status_code == 400
    assert 'Weak password' in json.loads(response.data)['error']

def test_register_existing_user(client):
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    response = client.post('/register', json=data)
    assert response.status_code == 400
    assert 'User already exists' in json.loads(response.data)['error']

def test_login_success_without_mfa(client):
    # Register user
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    # Login
    response = client.post('/login', json=data)
    assert response.status_code == 200
    assert 'Login successful' in json.loads(response.data)['message']
    assert 'token' in json.loads(response.data)

def test_login_wrong_password(client):
    # Register user
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    # Login with wrong password
    wrong_data = {'email': 'test@example.com', 'password': 'WrongPass123'}
    response = client.post('/login', json=wrong_data)
    assert response.status_code == 401
    assert 'Incorrect password' in json.loads(response.data)['error']

def test_enable_mfa(client):
    # Register user
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    # Enable MFA with correct OTP (assuming OTP is '123456' for test, but actually need to generate)
    # For test, we need to mock or calculate OTP
    import pyotp
    secret = users_db['test@example.com']['mfa_secret']
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    enable_data = {'email': 'test@example.com', 'otp': otp}
    response = client.post('/enable-mfa', json=enable_data)
    assert response.status_code == 200
    assert 'MFA enabled' in json.loads(response.data)['message']

def test_verify_mfa_success(client):
    # Register and enable MFA
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    import pyotp
    secret = users_db['test@example.com']['mfa_secret']
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    enable_data = {'email': 'test@example.com', 'otp': otp}
    client.post('/enable-mfa', json=enable_data)
    # Now login should require MFA
    login_response = client.post('/login', json=data)
    assert 'MFA required' in json.loads(login_response.data)['message']
    # Verify MFA
    verify_data = {'email': 'test@example.com', 'otp': totp.now()}
    response = client.post('/verify-mfa', json=verify_data)
    assert response.status_code == 200
    assert 'MFA verification successful' in json.loads(response.data)['message']
    assert 'token' in json.loads(response.data)

def test_verify_mfa_invalid_otp(client):
    # Register and enable MFA
    data = {'email': 'test@example.com', 'password': 'StrongPass123'}
    client.post('/register', json=data)
    import pyotp
    secret = users_db['test@example.com']['mfa_secret']
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    enable_data = {'email': 'test@example.com', 'otp': otp}
    client.post('/enable-mfa', json=enable_data)
    # Verify with wrong OTP
    verify_data = {'email': 'test@example.com', 'otp': '000000'}
    response = client.post('/verify-mfa', json=verify_data)
    assert response.status_code == 401
    assert 'Invalid OTP' in json.loads(response.data)['error']

def test_logout(client):
    response = client.post('/logout')
    assert response.status_code == 200
    assert 'Logout successful' in json.loads(response.data)['message']