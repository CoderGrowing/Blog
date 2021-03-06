#coding:utf-8
from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown
from flask_moment import Moment

import mistune
from pygments import highlight

from pygments import lexers
from pygments import formatters

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'main.user_login'

bootstrap = Bootstrap()
mail = Mail()
db = SQLAlchemy()
pagedown = PageDown()
moment = Moment()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    app.config['BOOTSTRAP_SERVE_LOCAL'] = True
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    moment.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

class HighlightRenderer(mistune.Renderer):
    def block_code(self, code, lang):
        if not lang:
            return '\n<pre><code>%s</code></pre>\n' % \
                mistune.escape(code)
        lexer = lexers.get_lexer_by_name(lang, stripall=True)
        formatter = formatters.HtmlFormatter()
        return highlight(code, lexer, formatter)

renderer = HighlightRenderer()
markdowner = mistune.Markdown(renderer=renderer, hard_wrap=True)