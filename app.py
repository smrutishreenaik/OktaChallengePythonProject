import os
import json
import requests
from flask import Flask, redirect, request, session, url_for, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import jwt

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Configure OAuth
oauth = OAuth(app)
okta = oauth.register(
    name="okta",
    client_id=os.getenv("OKTA_CLIENT_ID"),
    client_secret=os.getenv("OKTA_CLIENT_SECRET"),
    authorize_url=os.getenv("OKTA_AUTHORIZATION_SERVER"),
    access_token_url=os.getenv("OKTA_TOKEN_ENDPOINT"),
    userinfo_endpoint=os.getenv("OKTA_USERINFO_ENDPOINT"),
    server_metadata_url=os.getenv("OKTA_SERVER_METADATA_URL"),
    jwks_uri=os.getenv("JWKS_URI"),
    client_kwargs={
        "scope": "openid profile email",
    },
)

# Home route
@app.route("/")
def home():
    return "Welcome to the Flask Okta Authentication App!"

# Login route
@app.route("/login")
def login():
    return okta.authorize_redirect(redirect_uri=os.getenv("OKTA_REDIRECT_URI"))

# Callback route (Okta will redirect here after authentication)
@app.route("/callback")
def callback():
    try:
        token = okta.authorize_access_token()
        session["user"] = token
        app.logger.info(token)
        return redirect(url_for("profile"))
    except Exception as e:
        app.logger.info(f"An error occurred: {e}")

# Profile route (fetch user info from Okta)
@app.route("/profile")
def profile():
    user_info = session.get("user")
    if not user_info:
        return redirect(url_for("login"))
    
    id_token = user_info.get("id_token")
    
    # Decode JWT to verify user identity
    decoded_jwt = jwt.decode(id_token, options={"verify_signature": False})
    
    return jsonify(decoded_jwt)

# Logout route
@app.route("/logout")
def logout():
    app.logger.info(session)
    session.clear()
    app.logger.info(session)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"),host="localhost", port=8080, debug=True)
