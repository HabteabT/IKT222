from flask import Flask, render_template, request, redirect, url_for, request, redirect, session, flash
from models import db, Post, User
import bleach
import os
from functools import wraps
from flask_limiter import Limiter
from datetime import datetime, timedelta
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)

 # adding the rate limiter to prevent Brute Force Attacks
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()

#added for assignment 2
@app.before_request
def loginCheck():
    open_routes = ['login_get', 'login', 'register', 'static']
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return redirect(url_for('register'))
        
        newUser = User.createUser(username, password)
        db.session.add(newUser)
        db.session.commit()

        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET'])
def login_get():
    if 'mandatory-time-out' in session and datetime.now() < session['mandatory-time-out']:
        return redirect(url_for('login_get'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute", methods=["POST"])
def login():
    if 'mandatory-time-out' in session and datetime.now() < session['mandatory-time-out']:
        return redirect(url_for('login_get'))

    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and user.verify_password(password):
        session.pop('attempts', None) 
        session.pop('mandatory-time-out', None) 
        session['user_id'] = user.id
        return redirect(url_for('index'))

    session['attempts'] = session.get('attempts', 0) + 1
    if session['attempts'] > 3:
        session['mandatory-time-out'] = datetime.now() + timedelta(minutes=3)
    else:
        flash("Incorrect credentials.")

    return redirect(url_for('login_get'))


if __name__ == '__main__':
    app.run(debug=True)
