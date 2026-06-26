import json
import logging
import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from auto_login import auto_login

# Load environment variables from .env file (for local development)
load_dotenv()

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
        if not proxy:
            proxy = os.environ.get("DEFAULT_PROXY")
            
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
            
            # Kiểm tra proxy hoạt động và log ra IP bằng ipwho.is
            try:
                import requests as simple_requests
                logger.info("Checking proxy connection via https://ipwho.is/...")
                test_resp = simple_requests.get("https://ipwho.is/", proxies=proxies_dict, timeout=10)
                if test_resp.status_code == 200:
                    ip_data = test_resp.json() or {}
                    logger.info(
                        f"Proxy test success! Outgoing IP: {ip_data.get('ip')} "
                        f"({ip_data.get('country')}, {ip_data.get('city')})"
                    )
                else:
                    logger.warning(f"Proxy test failed with HTTP status code: {test_resp.status_code}")
            except Exception as test_err:
                logger.error(f"Failed to connect through proxy: {test_err}")

        webhook_url = data.get("webhook_url") or os.environ.get("DEFAULT_WEBHOOK_URL") or None

        logger.info(f"Initiating auto-login for email: {email}")
        
        # 4. Perform the auto-login flow (disable disk output)
        result = auto_login(
            email=email,
            password=password,
            totp_secret=totp_secret,
            proxies=proxies_dict,
            output_file=False,
            webhook_url=webhook_url
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
    import os
    # Read port dynamically from environment variable (required for Heroku)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
