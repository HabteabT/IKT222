from idlelib import redirector
from pexpect import expect
from flask import Flask, url_for, request, redirect, session, jsonify, render_template
from data.models import db, User
import os
from datetime import datetime, timezone, timedelta
import requests
import arrow
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session handling

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()  # This will

    # create a dummy user
    if not User.query.filter_by(username="admin").first():
        newUser = User.createUser("admin", "admin")
        db.session.add(newUser)
        db.session.commit()

# right now all the scopes for this oauth server has been set to reading of username
# however in the real world this would be provided by the request or in the configuration
# of the oauth for the application. But this was much simpler to do for this task

# Mock constants for client ID and secret.
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/callback"

AUTH_CODES = {}  # Temporary storage for auth codes. Use a proper database in a real-world scenario.
TOKENS = {}      # Temporary storage for access tokens.

def validate(client_id, redirect_uri, client_secret=None, code=None):
    if client_secret is None and code is None:
        # First validation logic
        return client_id == CLIENT_ID and redirect_uri == REDIRECT_URI
    else:
        # Second validation logic
        return (
            code in AUTH_CODES
            and AUTH_CODES[code]["client_id"] == client_id
            and client_id == CLIENT_ID
            and client_secret == CLIENT_SECRET
        )
    
# TODO:
# 1. Extract 'client_id', 'redirect_uri', 'state', etc. from the request.
# 2. Validate 'client_id' and 'redirect_uri' against registered client details.
# 3. Display an authorization page to the user to grant permission.
# 4. If user grants permission, generate an authorization code.
# 5. Save the authorization code and associated data.
# 6. Redirect the user back to 'redirect_uri' with the 'code' and 'state'.
@app.route("/auth", methods=["GET"])
def auth():
    """
    Endpoint where the client sends the user to request their authorization.
    After authorization, user is redirected back to the client with an auth code.
    """
    try:
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        state = request.args.get("state")

        if not validate(client_id, redirect_uri):
            return jsonify({"error": "Permission Denied"}), 403

        # authenticate user
        if 'user_id' not in session:
            session['next_url'] = request.url
            return redirect(url_for('login'))

        # ask for consent for the application scope
        if 'consent' not in session:
            session['next_url'] = request.url
            return redirect(url_for('consent'))

        # generate an authorization code if the user is logged in
        auth_code = str(uuid.uuid4())
        AUTH_CODES[auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "user_id": session["user_id"],
            "expires_at": datetime.now(timezone.utc).timestamp() + 600
        }
        # Redirect the user back to 'redirect_uri' with the 'code' and 'state'
        return redirect(f"{redirect_uri}?code={auth_code}&state={state}")

    except Exception as e:
        print(e)
        return jsonify({"error": "Permission Denied"}), 403



# TODO:
# 1. Extract 'code', 'redirect_uri', 'client_id', 'client_secret' from the request.
# 2. Verify that the 'code' is valid and has not expired.
# 3. Validate 'client_id' and 'client_secret'.
# 4. Generate an access token (and optionally, a refresh token).
# 5. Save the access token for later validation.
# 6. Return the access token (and optionally, a refresh token) in a JSON response.
@app.route("/token", methods=["POST"])
def token():
    """
    Endpoint where the client exchanges the authorization code for an access token.
    """

    # gather the information from the request
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    # validate the code and client details
    if not validate(client_id, redirect_uri, client_secret, code):
        return jsonify({"error": "invalid_grant"}), 400

    # generate and save access token
    access_token = str(uuid.uuid4())
    TOKENS[access_token] = {
        "client_id": client_id,
        "user_id": AUTH_CODES.get(code)["user_id"],
        "scopes": ["read:username"],
        "expires_at": datetime.now(timezone.utc).timestamp() + 3600
    }

    # invalidate the authorization code (one-time use)
    del AUTH_CODES[code]

    return jsonify({"access_token": access_token, "token_type": "Bearer"})



# TODO:
# 1. Extract the access token from the request's Authorization header.
# 2. Validate the access token.
# 3. If valid, proceed to access the protected resource and return the data.
# 4. If invalid, return an appropriate error response.
@app.route("/protected_resource", methods=["GET"])
def protected_resource():
    """
    A protected endpoint the client can access using the access token.
    """
    header = request.headers.get("Authorization")
    if not header or not header.startswith("Bearer "):
        return jsonify({"error": "invalid_request", "message": "Authorization header missing or malformed"}), 401

    access_token = header.split(" ")[1]

    try:
        if access_token in TOKENS:
            info = TOKENS.get(access_token)
            user = User.query.filter_by(id=info["user_id"]).first()
            return jsonify({"username": user.username, "token": access_token, "expires_at": info["expires_at"]})
        else:
            return jsonify({"error": "invalid_token", "message": "Token invalid or expired"}), 401
        pass
    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error", "message": "Something went wrong"}), 500

# so the user can get their authentication from oauth server
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # check if theres a timeout in effect
        if 'mandatory-time-out' in session and datetime.now() < session['mandatory-time-out']:
            return redirect(url_for('login'))

        # authenticate user
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.verify_password(password):
            session.pop('attempts', None) 
            session.pop('mandatory-time-out', None)
            session['user_id'] = user.id

            next_url = session.pop('next_url', REDIRECT_URI)
            print(next_url)
            return redirect(next_url)

        # handle login failure
        session['attempts'] = session.get('attempts', 0) + 1
        if session['attempts'] > 3:
            session['mandatory-time-out'] = datetime.now() + timedelta(minutes=3)
        else:
            flash("Incorrect credentials.")
        return redirect(url_for("login"))

    return render_template("base.html")


#so the user can consent to the data being read
@app.route("/consent", methods=["GET", "POST"])
def consent():
    if request.method == "POST":
        session['consent'] = True
        next_url = session.pop('next_url', REDIRECT_URI)
        return redirect(next_url)
    return render_template("consent.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
