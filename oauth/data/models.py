from flask_sqlalchemy import SQLAlchemy
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    username = db.Column(db.String(100), nullable= False)
    id = db.Column(db.Integer, primary_key=True)
    hashedPassword = db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    @classmethod
    def createUser(cls, username, password):
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return cls(username=username, hashedPassword=hashedPassword)

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.hashedPassword)
