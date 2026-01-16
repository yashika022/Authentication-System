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

## User Interface

The application provides a modern web interface at `http://localhost:5000` built with Tailwind CSS featuring:
- **Login Tab:** Authenticate with email and password (with MFA support)
- **Register Tab:** Create new account with strong password requirements
- **MFA Setup:** Scan QR code with Google Authenticator or Authy during registration
- **Dashboard:** Access after successful authentication

## API Endpoints

### GET /
Returns the main HTML dashboard/login interface.

**Response:** HTML page with interactive login and registration forms

### POST /register
Registers a new user and generates MFA credentials.

**Request Body (JSON API):**
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "StrongPass123"
}
```

**Response (Success):**
```json
{
  "message": "Registration successful",
  "mfa_qr_data_url": "data:image/png;base64,...",
  "mfa_provisioning_uri": "otpauth://totp/SecureAuthApp/user@example.com?secret=...",
  "mfa_secret": "BASE32SECRET"
}
```

**GET /register-form**
Returns an HTML registration form for web-based registration.

**Password Policy:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

### GET /show-qr
Displays a QR code in the browser for scanning with an authenticator app.

**Response:** HTML page with QR code image and secret key

### POST /login
Authenticates a user with email and password.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "StrongPass123"
}
```

**Response (Success, no MFA enabled):**
```json
{
  "message": "Login successful",
  "token": "JWT_TOKEN_HERE"
}
```

**Response (MFA enabled):**
```json
{
  "message": "MFA required, verify using /verify-mfa"
}
```

**Rate Limit:** 3 attempts per minute

### GET /login-form
Returns an HTML login form for web-based authentication.

**Response:** HTML page with login form

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
Verifies MFA OTP code and issues JWT token upon successful verification.

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response (Success):**
```json
{
  "message": "MFA verification successful",
  "token": "JWT_TOKEN_HERE"
}
```

**Response (Failure):**
```json
{
  "error": "Invalid OTP"
}
```

**Rate Limit:** 5 attempts per minute

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

### Prerequisites
- Python 3.12+
- pip (Python package manager)

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yashika022/Authentication-System.git
   cd Authentication-System
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or manually install:
   ```bash
   pip install flask pyotp qrcode[pil] pillow bcrypt pyjwt flask-limiter qrcode-terminal
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Access the web interface:**
   - Open browser to `http://localhost:5000`
   - Register a new account
   - Scan QR code with Google Authenticator or Authy
   - Login and verify MFA

### Command-Line Registration

You can also register users from the command line:

```bash
python app.py --register
```

This will prompt for email, name, and password, then display the MFA QR code in your terminal.