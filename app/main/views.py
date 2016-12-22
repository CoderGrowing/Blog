#coding:utf-8

from flask import render_template, redirect, url_for, flash, current_app, request
from app.main import main
from .forms import UserLoginForm, RegisterForm, CommentForm, EditProfileForm, ChangePasswordForm
from app.models import db, Article, User, Comment
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime


@main.route('/', methods=['POST', 'GET'])
def index():
    page = request.args.get('page', 1, type=int)

    if current_user.is_authenticated and current_user.role == 'Admin':
        pagination = Article.query.order_by(Article.timestamp.desc()).paginate(
            page, per_page=20, error_out=False)
    else:
        pagination = Article.query.filter_by(permission='common').\
            order_by(Article.timestamp.desc()).paginate(page, per_page=20, error_out=False)

    posts = pagination.items
    limit_posts = posts[0:5]

    return render_template('index.html', posts=posts, pagination=pagination, limit_posts=limit_posts)

@main.route('/admin', methods=['POST', 'GET'])
@login_required
def admin():
    if current_user.role != "Admin":
        flash(u'您没有权限访问该页面！')
        return render_template('index.html')
    else:
        return render_template('admin.html')

@main.route('/write-article', methods=['GET', 'POST'])
@login_required
def write_article():
    if current_user.role != "Admin":
        flash(u'您没有权限访问该页面！')
        return render_template('index.html')
    if request.method == 'POST':
        article = Article(heading=request.form['heading'], body=request.form['article'],
                          article_type=request.form['article_type'], permission=request.form['permission'])
        db.session.add(article)
        return redirect(url_for('main.index'))

    return render_template('write-article.html')

@main.route('/edit-article/<int:id>', methods=['POST', 'GET'])
@login_required
def edit_article(id):
    if current_user.role != "Admin":
        flash(u'您没有权限访问该页面！')
        return render_template('index.html')

    post = Article.query.get_or_404(id)
    if request.method == 'POST':
        post.heading = request.form['heading']
        post.body = request.form['article']
        post.timestamp = datetime.now()
        db.session.add(post)
        flash(u'文章修改成功！')
        return redirect(url_for('main.index'))

    return render_template('edit-article.html', post=post, id=id)

@main.route('/article-list', methods=['POST', 'GET'])
@login_required
def article_list():
    if current_user.role != "Admin":
        flash(u'您没有权限访问该页面！')
        return render_template('index.html')

    posts = Article.query.order_by(Article.timestamp.desc()).all()

    return render_template('article-list.html', posts=posts)

@main.route('/user-login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('main.index'))
        flash(u'用户名或密码错误')
    return render_template('user-login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        flash(u'注册成功！')
        return redirect(url_for('main.user_login'))
    return render_template('register.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'注销成功！')
    return redirect(url_for('main.index'))

@main.route('/article/<int:id>/<string:name>', methods=['POST', 'GET'] )
def article(id, name):
    if Article.query.get(id) and Article.query.filter_by(heading=name).first():
        post = Article.query.get_or_404(id)
    else:
        flash(u'您要找的文章不存在！')
        return redirect(url_for('main.index'))

    if current_user.is_authenticated and current_user.role == 'Admin':
        limit_posts = Article.query.order_by(Article.timestamp.desc()).all()[0:5]
    else:
        limit_posts = Article.query.filter_by(permission='common').order_by(Article.timestamp.desc()).all()[0:5]

    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(body=form.body.data,post=post)
            db.session.add(comment)
            flash(u'评论提交成功！')
            return redirect(url_for('main.article', id=post.id, name=post.heading, page=-1))
        flash(u'请先登录后再进行评论！')
        return redirect(url_for('main.user_login'))

    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) / 20 + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=20, error_out=False
    )
    comments = pagination.items

    return render_template('article.html', posts=[post], form=form,
                           comments=comments, pagination=pagination, limit_posts=limit_posts)

@main.route('/article-type/<string:type>')
def article_type(type):

    page = request.args.get('page', 1, type=int)
    pagination = Article.query.filter_by(article_type=type).order_by(Article.timestamp.desc()).paginate(
        page, per_page=20, error_out=False)

    posts = pagination.items

    return render_template('article-type.html', posts=posts, pagination=pagination)


@main.route('/edit-profile', methods=['POST', 'GET'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.name.data
        db.session.add(current_user)
        flash(u'昵称修改成功！')
        return redirect(url_for('main.index', username=current_user.username))

    return render_template('edit-profile.html', form=form)

@main.route('/change-password', methods=['POST', 'GET'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            flash(u'密码修改成功！')
            return redirect(url_for('main.index'))
        else:
            flash(u'密码错误，请确认您输入的密码是否正确')

    return render_template('change-password.html', form=form)
