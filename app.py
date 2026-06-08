import json
import logging
from flask import Flask, request, jsonify
from auto_login import auto_login

# Configure Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route("/api/login", methods=["POST"])
def login_api():
    """
    POST API Endpoint to perform GPT Auto Login.
    Request body (JSON):
    {
        "email": "user@example.com",       # Required
        "password": "your_password",       # Required
        "2fa": "2FA_SECRET_HERE",          # Optional (or "totp_secret")
        "proxy": "http://user:pass@ip:port"# Optional
    }
    
    Response (JSON):
    - Success (HTTP 200):
      {
          "status": "success",
          "cookie_string": "oai-did=...; __Host-next-auth.csrf-token=...;"
      }
    - Error (HTTP 400 / 500):
      {
          "status": "error",
          "message": "Detailed error message"
      }
    """
    try:
        # 1. Parse JSON payload
        data = request.get_json(silent=True) or {}
        
        email = data.get("email")
        password = data.get("password")
        totp_secret = data.get("2fa") or data.get("totp_secret") or None
        proxy = data.get("proxy")
        
        # 2. Input validation
        if not email or not password:
            return jsonify({
                "status": "error",
                "message": "Email and password are required parameters."
            }), 400
            
        # 3. Format proxies if provided
        proxies_dict = None
        if proxy:
            proxy = proxy.strip()
            # Basic validation/cleanup of proxy scheme
            if not proxy.startswith(("http://", "https://", "socks5://", "socks4://")):
                proxy = "http://" + proxy
            proxies_dict = {
                "http": proxy,
                "https": proxy
            }
            logger.info(f"Using proxy: {proxy}")

        logger.info(f"Initiating auto-login for email: {email}")
        
        # 4. Perform the auto-login flow (disable disk output)
        result = auto_login(
            email=email,
            password=password,
            totp_secret=totp_secret,
            proxies=proxies_dict,
            output_file=False
        )
        
        # 5. Build and return responses
        if result.get("status") == "success":
            logger.info(f"Login successful for email: {email}")
            return jsonify({
                "status": "success",
                "cookie_string": result.get("cookie_string", "")
            }), 200
        else:
            error_message = result.get("message", "Unknown error occurred during login.")
            logger.error(f"Login failed for email {email}: {error_message}")
            return jsonify({
                "status": "error",
                "message": error_message
            }), 400

    except Exception as e:
        logger.exception("Internal server error in /api/login endpoint")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


if __name__ == "__main__":
    # Start the Flask development server on host 0.0.0.0 and port 5000
    app.run(host="0.0.0.0", port=5000, debug=True)
