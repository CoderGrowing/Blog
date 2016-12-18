#coding:utf-8
#工厂函数，初始化所有用到的扩展
from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown
from flask_simplemde import SimpleMDE
from flask_moment import Moment

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'main.admin_login'

bootstrap = Bootstrap()
mail = Mail()
db = SQLAlchemy()
pagedown = PageDown()
simplemde = SimpleMDE()
moment = Moment()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    simplemde.init_app(app)
    moment.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
