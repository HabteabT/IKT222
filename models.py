from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pyotp

db = SQLAlchemy()


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Post {self.title}>'


class User(db.Model):
    username = db.Column(db.String(100), nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    hashedPassword = db.Column(db.LargeBinary, nullable=True)
    oauth_provider = db.Column(db.String(100), nullable=True)
    twofactor = db.Column(db.String(32), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    @classmethod
    def createUser(cls, username, password):
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        twofactor = pyotp.random_base32()
        return cls(username=username, hashedPassword=hashedPassword, twofactor = twofactor)

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.hashedPassword)
