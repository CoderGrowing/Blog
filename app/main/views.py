#coding:utf-8

from flask import render_template, redirect, url_for, flash, current_app, request
from app.main import main
from .forms import AdminLoginForm, UserLoginForm, RegisterForm, CommentForm, EditProfileForm, ChangePasswordForm
from app.models import db, Admin, Article, User, Comment
from flask_login import login_user, login_required, logout_user, current_user


@main.route('/', methods=['POST', 'GET'])
def index():
    posts=Article.query.order_by(Article.timestamp.desc()).all()

    ##存疑
    page = request.args.get('page', 1, type=int)
    #参数中的page为自己制定，  此处为加上  ?page=1
    pagination = Article.query.order_by(Article.timestamp.desc()).paginate(
        page, per_page=20, error_out=False)
    #items属性时当前页面的记录
    posts = pagination.items

    return render_template('index.html', posts=posts, pagination=pagination)

@main.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin is not None and admin.verify_password(form.password.data):
            login_user(admin)
            return redirect(request.args.get('next') or url_for('main.admin'))
        flash(u'用户名或密码错误', 'warning')
    return render_template('admin-login.html', form=form)

@main.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        article = Article(heading=request.form['heading'], body=request.form['article'])
        db.session.add(article)
        return redirect(url_for('main.index'))

    return render_template('admin.html')


#
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

@main.route('/article/<int:id>', methods=['POST', 'GET'] )
def article(id):
    post = Article.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          )
        db.session.add(comment)
        flash(u'评论提交成功！')
        return redirect(url_for('.article', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) / 20 + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=20, error_out=False
    )
    comments = pagination.items

    return render_template('article.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)

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




