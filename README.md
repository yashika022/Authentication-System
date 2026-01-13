# Secure Authentication System with MFA

This is a Flask-based secure authentication system implementing password hashing, JWT session management, and Multi-Factor Authentication (MFA) using TOTP (Time-based One-Time Password) compatible with Google Authenticator and Authy.

## Features

- Secure password storage using bcrypt
- JWT tokens for session management
- MFA integration with TOTP
- Password policy enforcement
- Rate limiting to prevent brute force attacks
- API endpoints for registration, login, logout, and MFA verification

## Tech Stack

- Python Flask
- bcrypt for password hashing
- PyJWT for JWT tokens
- pyotp for TOTP MFA
- qrcode for QR code generation
- Flask-Limiter for rate limiting

## API Endpoints

### GET /
Returns a welcome message indicating the system is running.

**Response:**
```json
{
  "message": "Auth System Running!"
}
```

### POST /register
Registers a new user.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "StrongPass123"
}
```

**Response (Success):**
```json
{
  "message": "Registration successful",
  "mfa_qr_data_url": "data:image/png;base64,...",
  "mfa_provisioning_uri": "otpauth://totp/...",
  "mfa_secret": "BASE32SECRET"
}
```

**Password Policy:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

### POST /login
Logs in a user.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "StrongPass123"
}
```

**Response (Success, no MFA):**
```json
{
  "message": "Login successful",
  "token": "JWT_TOKEN"
}
```

**Response (MFA required):**
```json
{
  "message": "MFA required, verify using /verify-mfa"
}
```

Rate limited to 3 attempts per minute.

### POST /enable-mfa
Enables MFA for a user after providing a valid OTP.

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "message": "MFA enabled successfully!"
}
```

### POST /verify-mfa
Verifies MFA OTP and issues JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "message": "MFA verification successful",
  "token": "JWT_TOKEN"
}
```

Rate limited to 5 attempts per minute.

### POST /logout
Logs out the user (client-side token deletion).

**Response:**
```json
{
  "message": "Logout successful! Delete token on client side."
}
```

## Security Considerations

### Password Security
- Passwords are hashed using bcrypt with a salt, providing strong protection against rainbow table attacks.
- Password policy enforces complexity to prevent weak passwords.

### Session Management
- JWT tokens are used for stateless session management.
- Tokens expire after 1 hour to limit exposure.
- Tokens include email, expiration, and issued-at claims.

### Multi-Factor Authentication
- TOTP provides time-based one-time passwords, adding a second factor beyond password.
- QR codes are generated for easy setup in authenticator apps.
- MFA is required after initial login if enabled.

### Rate Limiting
- Login attempts are limited to 3 per minute to prevent brute force attacks.
- MFA verification is limited to 5 per minute.
- Uses in-memory storage (not suitable for production; use Redis or database in production).

### Common Attack Mitigations
- **Brute Force:** Rate limiting on login and MFA endpoints.
- **Replay Attacks:** JWT tokens have expiration and are stateless; TOTP codes are time-based and expire.
- **Password Cracking:** bcrypt hashing with salt.
- **Session Hijacking:** JWT tokens are signed; use HTTPS in production.
- **Weak Passwords:** Enforced password policy.

### Production Considerations
- Use a proper database instead of in-memory storage.
- Configure a persistent storage backend for rate limiting (e.g., Redis).
- Use a strong, randomly generated SECRET_KEY.
- Enable HTTPS.
- Implement proper logging and monitoring.
- Use environment variables for sensitive configuration.
- Consider using OAuth2 instead of JWT for more advanced scenarios.

## Running the Application

1. Install dependencies: `pip install flask pyotp qrcode[pil] pillow bcrypt pyjwt flask-limiter`
2. Run: `python app.py`
3. Access at `http://localhost:5000`

## Testing

Run tests with: `python -m pytest test_app.py -v`

Tests cover successful flows and failure cases for all endpoints.