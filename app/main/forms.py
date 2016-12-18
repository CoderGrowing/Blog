#coding:utf-8

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateTimeField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from app.models import User

class AdminLoginForm(FlaskForm):
    username = StringField(u'用户名', validators=[DataRequired()])
    password = PasswordField(u'密码', validators=[DataRequired()])
    submit = SubmitField(u'登录')


class UserLoginForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Length(1, 64),
                                           Email(message=u'请输入有效的邮箱地址')])
    password = PasswordField(u'密码', validators=[DataRequired()])
    remember_me = BooleanField(u'记住我')
    submit = SubmitField(u'登录')

class RegisterForm(FlaskForm):
    email = StringField(u'邮箱', validators=[DataRequired(), Length(1, 64),
                                           Email()])
    username = StringField(u'用户名', validators=[DataRequired()])
    password = PasswordField(u'密码', validators=[DataRequired(), Length(6, 16, message=u'密码必须为6-16位'),
                                                EqualTo('password2', message=u'两次输入的密码不一致')])
    password2 = PasswordField(u'确认密码', validators=[DataRequired()])
    submit = SubmitField(u'注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'该邮箱已经注册！')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'用户名已被注册')


class CommentForm(FlaskForm):
    body = StringField('', validators=[DataRequired()])
    submit = SubmitField(u'提交')


class EditProfileForm(FlaskForm):
    name = StringField(u'新的昵称', validators=[Length(0, 64)])
    submit = SubmitField(u'提交')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(u'请输入旧密码', validators=[DataRequired()])
    new_password = PasswordField(u'请输入新密码', [DataRequired(), Length(6, 16, message=u'密码必须为6-16位'),
                                              EqualTo('new_password2', message=u'两次输入的密码不一致')])
    new_password2 = PasswordField(u'确认新密码', validators=[DataRequired()])
    submit = SubmitField(u'提交')



