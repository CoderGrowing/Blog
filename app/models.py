#coding:utf-8
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from . import markdowner
import hashlib
from flask import request


articletags = db.Table('articletags',
                        db.Column('tag_id', db.Integer, db.ForeignKey('tags.id')),
                        db.Column('article_id', db.Integer, db.ForeignKey('articles.id')))


class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    articles = db.relationship('Article',
                               secondary=articletags,
                               backref=db.backref('tags', lazy='dynamic'), lazy='dynamic')


class Article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    heading = db.Column(db.Text)
    body = db.Column(db.Text)
    article_type = db.Column(db.Text)
    article_len = db.Column(db.Integer)
    permission = db.Column(db.String(64))
    
    timestamp = db.Column(db.String(64), index=True, default=datetime.now)
    edit_timestamp = db.Column(db.String(64), index=True, default=datetime.now)
    comments = db.relationship('Comment', backref='article', lazy='dynamic')
    reply_comments = db.relationship('ReplyComment', backref='article', lazy='dynamic')

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
        target.body_html = markdowner(value)
        target.preview = target.body_html[0:400]


db.event.listen(Article.body, 'set', Article.on_changed_body)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True)
    timestamp = db.Column(db.String(64), index=True, default=datetime.now)
    password_hash = db.Column(db.String(128))
    avatar_hash = db.Column(db.String(32))
    comments = db.relationship('Comment', backref='user', lazy='dynamic')
    reply_comments = db.relationship('ReplyComment', backref='user', lazy='dynamic')
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

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating
        )


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.String(64), index=True, default=datetime.now)
    disabled = db.Column(db.Boolean)
    has_reply = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    article_id = db.Column(db.Integer, db.ForeignKey('articles.id'))
    reply_comment = db.relationship('ReplyComment', backref='comment', lazy='dynamic')


class ReplyComment(db.Model):
    __tablename__ = 'reply_comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.String(64), index=True, default=datetime.now)
    disabled = db.Column(db.Boolean)
    reply_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    reply_reply_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    article_id = db.Column(db.Integer, db.ForeignKey('articles.id'))
    db.relationship('ReplyComment', backref='replycomment', lazy='dynamic')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))