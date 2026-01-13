from app import app, users_db
import json
import pyotp

print("=== Authentication System Demo ===\n")

# Clear db for fresh demo
users_db.clear()

with app.test_client() as client:
    # 1. Check home
    print("1. Testing home endpoint...")
    response = client.get('/')
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 2. Register user
    print("2. Registering user...")
    data = {"email": "demo@example.com", "name": "Demo User", "password": "StrongPass123"}
    response = client.post('/register', json=data)
    print(f"Status: {response.status_code}")
    resp_json = json.loads(response.data)
    print(f"Response: {json.dumps(resp_json, indent=2)}")
    mfa_secret = resp_json["mfa_secret"]
    print()

    # 3. Login without MFA
    print("3. Logging in without MFA...")
    response = client.post('/login', json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 4. Enable MFA
    print("4. Enabling MFA...")
    totp = pyotp.TOTP(mfa_secret)
    otp = totp.now()
    print(f"Generated OTP: {otp}")
    enable_data = {"email": "demo@example.com", "otp": otp}
    response = client.post('/enable-mfa', json=enable_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 5. Login with MFA required
    print("5. Logging in (MFA now required)...")
    response = client.post('/login', json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 6. Verify MFA
    print("6. Verifying MFA...")
    otp = totp.now()
    print(f"Current OTP: {otp}")
    verify_data = {"email": "demo@example.com", "otp": otp}
    response = client.post('/verify-mfa', json=verify_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 7. Test wrong password
    print("7. Testing wrong password...")
    wrong_data = {"email": "demo@example.com", "password": "WrongPass123"}
    response = client.post('/login', json=wrong_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

    # 8. Test invalid OTP
    print("8. Testing invalid OTP...")
    verify_data = {"email": "demo@example.com", "otp": "000000"}
    response = client.post('/verify-mfa', json=verify_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.loads(response.data)}")
    print()

print("=== Demo Complete ===")