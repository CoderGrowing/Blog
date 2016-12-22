#coding:utf-8
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from markdown import markdown
import bleach

class Article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    heading = db.Column(db.Text)
    body = db.Column(db.Text)
    article_type = db.Column(db.Text)
    permission = db.Column(db.String(64))
    preview = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    body_html = db.Column(db.Text)

#随机博客文章生成器
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        for i in range(count):
            p = Article(body=forgery_py.lorem_ipsum.sentences(randint(3, 6)),
                        timestamp=forgery_py.date.date(True),
                        heading=forgery_py.lorem_ipsum.title())
            db.session.add(p)
            db.session.commit()
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True
        ))
        target.preview = target.body_html[0:400]

db.event.listen(Article.body, 'set', Article.on_changed_body)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String, default='User')


    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now)
    disabled = db.Column(db.Boolean)
    article_id = db.Column(db.Integer, db.ForeignKey('articles.id'))



@login_manager.user_loader
def load_admin(admin_id):
    return Admin.query.get(int(admin_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))