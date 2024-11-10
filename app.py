from flask import Flask, render_template, request, redirect, url_for, request, redirect, session, flash, send_file
from models import db, Post, User
import bleach
import requests
import os
import secrets
from functools import wraps
from flask_limiter import Limiter
from datetime import datetime, timedelta
from flask_limiter.util import get_remote_address
from io import BytesIO
import qrcode
import pyotp

app = Flask(__name__)
app.secret_key = os.urandom(24)

 # adding the rate limiter to prevent Brute Force Attacks
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


CLIENT_ID = "1234567890abcdef"
CLIENT_SECRET = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
REDIRECT_URL = "http://localhost:5000/callback"
STATE = secrets.token_urlsafe(16)
OAUTH_SERVER_URL = "http://localhost:5001"

OAUTH_DATA = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URL,
    "state": STATE,
    "oauth_server_uri": OAUTH_SERVER_URL
}

db.init_app(app)
with app.app_context():
    db.create_all()

#added for assignment 2
@app.before_request
def loginCheck():
    open_routes = ['login_get', 'login', 'register', 'static', 'callback']
    if 'user_id' not in session and request.endpoint not in open_routes:
        return redirect(url_for('login_get'))

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def detect_xss(content):
    if content.strip() == "<script>alert('XSS Vulnerability!');</script>":
        print("XSS Vulnerability detected!")
        return True
    return False

def cleanInput(content):

    tag = ['p']
    attributes = {
        'a': ['title'],
    }
    newContent = bleach.clean(content, tags=tag, attributes=attributes, strip=True)
    return newContent

def clean_output(content):
    tag = ['p']
    attributes = {}
    
    sanitized_content = bleach.clean(content, tags=tag, attributes=attributes, strip=True)
    return sanitized_content


@app.route('/')
def index():
    posts = Post.query.all()
    for post in posts:
        post.content = clean_output(post.content)
        
    return render_template('index.html', posts=posts)

@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        title = clean_output(request.form['title'])
        content = clean_output(request.form['content'])  

        new_post = Post(title=title, content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('create_post.html')


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    sanitized_content = clean_output(post.content)
    return render_template('post.html', post=post, sanitized_content=sanitized_content)

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if request.method == 'POST':
        content = cleanInput(request.form['content'])
        post.title = cleanInput(request.form['title'])
        post.content = content
        db.session.commit()
        return redirect(url_for('post', post_id=post.id))

    return render_template('edit_post.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))


# Assignment 2:

@app.route('/display_qr_code')
def display_qr_code():
    buffer = BytesIO()
    qrcode.save(buffer)
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username, oauth_provider=None).first():
            return redirect(url_for('register'))

        newUser = User.createUser(username, password)
        db.session.add(newUser)
        db.session.commit()

        totp = pyotp.TOTP(newUser.twofactor)
        uri = totp.provisioning_uri(name=username, issuer_name = "IKT222")
        qrcodeImage = qrcode.make(uri)
        buffer = BytesIO()
        qrcodeImage.save(buffer)
        buffer.seek(0)

        return send_file(buffer, mimetype='image/png')
    
    return render_template('register.html', oauth_data=OAUTH_DATA)


@app.route('/login', methods=['GET'])
def login_get():
    if 'mandatory-time-out' in session and datetime.now() < session['mandatory-time-out']:
        return redirect(url_for('login_get'))
    return render_template('login.html', oauth_data=OAUTH_DATA)

@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute", methods=["POST"])
def login():
    if 'mandatory-time-out' in session and datetime.now() < session['mandatory-time-out']:
        return redirect(url_for('login_get'))

    username = request.form['username']
    password = request.form['password']

    totp_code = request.form.get('totp_code')

    # oauth is not signed in here
    user = User.query.filter_by(username=username, oauth_provider=None).first()

    if user and user.verify_password(password):
        totp = pyotp.TOTP(user.twofactor)
        if totp.verify(totp_code):
            session.pop('attempts', None) 
            session.pop('mandatory-time-out', None) 
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login_get'))

    session['attempts'] = session.get('attempts', 0) + 1
    if session['attempts'] > 3:
        session['mandatory-time-out'] = datetime.now() + timedelta(minutes=3)
    else:
        flash("Incorrect credentials.")

    return redirect(url_for('login_get'))


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    # the authorization code is recieved here
    auth_code = request.args.get("code")
    state = request.args.get("state")
    if not auth_code:
        return "Authorization failed: no code returned", 400

    # Possible CSRF attack
    if state != STATE:
        return "State missmatch!", 403

    # exchange authorization code for access token
    token_response = requests.post(
        f"{OAUTH_SERVER_URL}/token",
        data={
            "code": auth_code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URL
        }
    )

    # parse the access token from response
    token_data = token_response.json()
    if "access_token" not in token_data:
        return "Failed to obtain access token", 400

    # get the protected data (username):
    access_token = token_data["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(f"{OAUTH_SERVER_URL}/protected_resource", headers=headers)
    if response.status_code != 200:
        print("Access denied:", response.status_code, response.json())
        return redirect("/login")

    # search if the user is already added to the database
    info = response.json()
    username = info.get("username")

    # if the user is already added to our database
    check_user = User.query.filter(User.username==username, User.oauth_provider.isnot(None)).first()
    if check_user:
        session["user_id"] = check_user.id

    else:
        # if not we add the user to the database
        # If user does not exist, create a new user in the database
        new_user = User(username=username, oauth_provider="custom")
        db.session.add(new_user)
        db.session.commit()
        session["user_id"] = new_user.id

    return redirect("/")


@app.route('/logout', methods=['GET'])
def logout():
    session.pop("user_id", None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
