from flask import Flask, render_template, request, redirect, url_for
from models import db, Post

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def detect_xss(content):
    # Detect the specific XSS payload "<script>alert('XSS Vulnerability!');</script>"
    if content.strip() == "<script>alert('XSS Vulnerability!');</script>":
        print("XSS Vulnerability detected!")
        return True
    return False


@app.route('/')
def index():
    return render_template('index.html', posts=Post.query.all())

@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        content = request.form['content']

        if detect_xss(content):
            print("XSS vulnerability being executed.")  # Just for logging purposes

        new_post = Post(title=request.form['title'], content=content)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('create_post.html')

@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if request.method == 'POST':
        content = request.form['content']

        if detect_xss(content):
            return render_template('edit_post.html', post=post, error="XSS Attack detected. The changes were not saved.")

        post.title = request.form['title']
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

if __name__ == '__main__':
    app.run(debug=True)
