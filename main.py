from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask_cors import CORS
import user_management as dbHandler
import os
from flask_wtf import CSRFProtect
from urllib.parse import urlparse, urljoin
import pyotp
import qrcode
import base64
from io import BytesIO
from flask import session

# Code snippet for logging a message
# app.logger.critical("message")


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "key")
csrf = CSRFProtect(app)
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)


allowed_origin = os.environ.get(
    "ALLOWED_ORIGIN", "https://cautious-robot-g46674v57559hvpj9-5000.app.github.dev/"
)
CORS(
    app,
    resources={r"/*": {"origins": [allowed_origin]}},
    supports_credentials=True,
)


@app.route("/totp", methods=["GET", "POST"])
def totp():
    if "username" not in session:
        return redirect("/")

    if request.method == "GET":
        # Use saved secret if it exists
        secret = dbHandler.get_totp_secret(session["username"])
        if not secret:
            secret = pyotp.random_base32()
            session["totp_secret"] = secret
        else:
            session["totp_secret"] = secret

        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=session["username"], issuer_name="The_Unsecure_PWA2"
        )

        img = qrcode.make(uri)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return render_template("totp.html", qr_code=qr_code)

    # POST: verify
    code = request.form["otp"]
    secret = session.get("totp_secret")
    print("OTP code:", code)
    print("Secret:", secret)
    print("Verify:", pyotp.TOTP(secret).verify(code))
    if secret and pyotp.TOTP(secret).verify(code):
        dbHandler.save_totp_secret(session["username"], secret)
        session["totp_verified"] = True
        return redirect("/success.html")

    return render_template("totp.html", qr_code=None)


@app.after_request
def set_security_headers(response):
    # Basic hardening
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # CSP (tight but safe for this app)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    return response


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def safe_redirect(target, fallback="/"):
    if target and is_safe_url(target):
        return redirect(target)
    return redirect(fallback)


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            session["username"] = username

            # If user already has TOTP set, require verification
            secret = dbHandler.get_totp_secret(username)
            if secret:
                session["totp_secret"] = secret
                return redirect("/totp")

            # If no secret yet, send them to setup
            return redirect("/totp")
        else:
            return render_template("/index.html")
    return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
