# Secure Authentication System with MFA

## Overview
A Flask-based secure authentication system implementing password hashing, JWT session management, and Multi-Factor Authentication (MFA) using TOTP compatible with Google Authenticator and Authy.

## Project Architecture
- **Framework**: Flask (Python)
- **Port**: 5000 (frontend webserver)
- **Database**: In-memory (temporary storage for demo purposes)

### Key Files
- `app.py` - Main Flask application with all authentication endpoints
- `test_app.py` - Test suite for the application
- `demo.py` - Demo script for testing the API

## Features
- Secure password storage using bcrypt
- JWT tokens for session management
- MFA integration with TOTP
- Password policy enforcement
- Rate limiting to prevent brute force attacks

## API Endpoints
- `GET /` - Health check
- `GET /show-qr` - Display MFA QR code demo
- `GET /register-form` - Web registration form
- `POST /register` - API registration endpoint
- `POST /login` - User login (rate limited: 3/min)
- `POST /enable-mfa` - Enable MFA for user
- `POST /verify-mfa` - Verify MFA code (rate limited: 5/min)
- `POST /logout` - User logout

## Recent Changes
- 2026-01-14: Configured to run on 0.0.0.0:5000 for Replit environment

## User Preferences
None documented yet.
