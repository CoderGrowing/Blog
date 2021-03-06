#coding:utf-8
import os
from app import create_app, db
from app.models import Article, User, Comment, ReplyComment, Tag, articletags
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app('default')
manager = Manager(app)
migrate = Migrate(app, db)

#????????????????????????????????????????????????????????????
def make_shell_context():
    return dict(app=app, db=db, Article=Article, User=User, Comment=Comment,
                ReplyComment=ReplyComment, Tag=Tag, articletags=articletags)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()