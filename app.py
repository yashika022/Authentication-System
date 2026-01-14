from flask import Flask, request, jsonify
import bcrypt
import jwt
import pyotp
import qrcode
import io
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
import qrcode_terminal

app = Flask(__name__)
app.config["SECRET_KEY"] = "ChangeThisToAStrongRandomKey"

# Rate limiting to stop brute force attacks
limiter = Limiter(get_remote_address, app=app)

# Temporary in-memory database
users_db = {}

# Password policy enforcement
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

# Home route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Auth System Running!"}), 200

# Show QR code in browser
@app.route("/show-qr", methods=["GET"])
def show_qr():
    # Generate new MFA secret each time for demo
    mfa_secret = pyotp.random_base32()

    # Generate provisioning URI and QR
    email = "demo@example.com"
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="SecureAuthApp")

    # Create QR image
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    qr_b64 = base64.b64encode(buf.read()).decode("utf-8")
    qr_data_url = f"data:image/png;base64,{qr_b64}"

    html = f"""
    <html>
    <head><title>MFA QR Code</title></head>
    <body>
    <h1>Scan this QR code with Google Authenticator or Authy</h1>
    <img src="{qr_data_url}" alt="MFA QR Code">
    <p>Secret: {mfa_secret}</p>
    <p>URI: {provisioning_uri}</p>
    </body>
    </html>
    """
    return html

# Web registration form
@app.route("/register-form", methods=["GET", "POST"])
def register_form():
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name", email)
        password = request.form.get("password")

        if not email or not password:
            return "<h1>Error: Email and password required</h1><a href='/register-form'>Back</a>"

        if email in users_db:
            return "<h1>Error: User already exists</h1><a href='/register-form'>Back</a>"

        if not is_strong_password(password):
            return "<h1>Error: Weak password! Use 8+ chars, 1 uppercase, 1 lowercase, 1 number</h1><a href='/register-form'>Back</a>"

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Create MFA secret
        mfa_secret = pyotp.random_base32()

        users_db[email] = {
            "name": name,
            "password": hashed_password,
            "mfa_secret": mfa_secret,
            "mfa_enabled": False
        }

        # Generate QR
        totp = pyotp.TOTP(mfa_secret)
        provisioning_uri = totp.provisioning_uri(name=name, issuer_name="SecureAuthApp")

        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        qr_b64 = base64.b64encode(buf.read()).decode("utf-8")
        qr_data_url = f"data:image/png;base64,{qr_b64}"

        html = f"""
        <html>
        <head><title>Registration Successful</title></head>
        <body>
        <h1>✅ Registration Successful!</h1>
        <p>User: {name} ({email})</p>
        <h2>📱 Scan this QR code with Google Authenticator or Authy</h2>
        <img src="{qr_data_url}" alt="MFA QR Code">
        <p><strong>Secret:</strong> {mfa_secret}</p>
        <p><strong>URI:</strong> {provisioning_uri}</p>
        <br>
        <a href="/login-form">Go to Login</a>
        </body>
        </html>
        """
        return html

    # GET: Show form
    html = """
    <html>
    <head><title>User Registration</title></head>
    <body>
    <h1>Register New User</h1>
    <form method="POST">
        <label>Email: <input type="email" name="email" required></label><br><br>
        <label>Name: <input type="text" name="name"></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <input type="submit" value="Register">
    </form>
    </body>
    </html>
    """
    return html

# User registration
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    name = data.get("name", email)  # default to email if no name
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    if email in users_db:
        return jsonify({"error": "User already exists"}), 400

    if not is_strong_password(password):
        return jsonify({"error": "Weak password! Use 8+ chars, 1 uppercase, 1 lowercase, 1 number"}), 400

    # Hash password with bcrypt
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Create MFA secret for TOTP
    mfa_secret = pyotp.random_base32()

    users_db[email] = {
        "name": name,
        "password": hashed_password,
        "mfa_secret": mfa_secret,
        "mfa_enabled": False
    }

    # Generate provisioning URI and a QR PNG data URL for Google Authenticator
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=name, issuer_name="SecureAuthApp")

    # Create QR image and encode as data URL (PNG)
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    qr_b64 = base64.b64encode(buf.read()).decode("utf-8")
    qr_data_url = f"data:image/png;base64,{qr_b64}"

    return jsonify({
        "message": "Registration successful",
        "mfa_qr_data_url": qr_data_url,
        "mfa_provisioning_uri": provisioning_uri,
        "mfa_secret": mfa_secret  # show only for learning, remove in real apps
    }), 200

# Login endpoint
@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute")
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = users_db.get(email)
    if not user:
        return jsonify({"error": "User not found"}), 401

    # Verify password
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "Incorrect password"}), 401

    # If MFA enabled, request OTP
    if user["mfa_enabled"]:
        return jsonify({"message": "MFA required, verify using /verify-mfa"}), 200

    # Generate JWT token
    token = jwt.encode({
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"message": "Login successful", "token": token}), 200

# Enable MFA (first time)
@app.route("/enable-mfa", methods=["POST"])
def enable_mfa():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    user = users_db.get(email)
    if not user:
        return jsonify({"error": "User not found"}), 401

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(otp):
        return jsonify({"error": "Invalid OTP"}), 401

    user["mfa_enabled"] = True
    return jsonify({"message": "MFA enabled successfully!"}), 200

# MFA verification
@app.route("/verify-mfa", methods=["POST"])
@limiter.limit("5 per minute")
def verify_mfa():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    user = users_db.get(email)
    if not user or not user["mfa_enabled"]:
        return jsonify({"error": "MFA not enabled for this user"}), 401

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(otp):
        return jsonify({"error": "Invalid OTP"}), 401

    # Issue JWT after MFA success
    token = jwt.encode({
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"message": "MFA verification successful", "token": token}), 200

# Logout (client deletes token)
@app.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "Logout successful! Delete token on client side."}), 200

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--register":
        # Interactive registration mode
        if len(sys.argv) == 5:
            # Command line args: email name password
            email = sys.argv[2]
            name = sys.argv[3]
            password = sys.argv[4]
        else:
            print("=== Interactive User Registration ===")
            email = input("Enter email: ").strip()
            name = input("Enter name: ").strip()
            password = input("Enter password: ").strip()

        # Validate password
        if not is_strong_password(password):
            print("Error: Weak password! Use 8+ chars, 1 uppercase, 1 lowercase, 1 number")
            sys.exit(1)

        # Register using test client
        with app.test_client() as client:
            data = {"email": email, "name": name, "password": password}
            response = client.post('/register', json=data)
            resp = response.get_json()

            if response.status_code == 200:
                print("\n✅ Registration successful!")
                provisioning_uri = resp['mfa_provisioning_uri']
                print("\n📱 Scan this QR code with Google Authenticator or Authy:")
                qrcode_terminal.draw(provisioning_uri)
                print(f"\n🔗 Or manually add: {provisioning_uri}")
                print(f"🔑 Secret: {resp['mfa_secret']} (keep this safe!)")
                print("\nNext steps:")
                print("1. Scan the QR code with your authenticator app")
                print("2. Run: python app.py")
                print("3. Login and enable MFA with the OTP from your app")
            else:
                print(f"❌ Registration failed: {resp.get('error', 'Unknown error')}")
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)
