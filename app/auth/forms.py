from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('信箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('密碼', validators=[DataRequired()])
    remember_me = BooleanField('保持登錄')
    submit = SubmitField('登錄')


class RegistrationForm(FlaskForm):
    email = StringField('信箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('用戶名', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               '用戶名只能包含字母、數字、點或底線')])
    password = PasswordField('密碼', validators=[
        DataRequired(), EqualTo('password2', message='密碼必須相同。')])
    password2 = PasswordField('確認密碼', validators=[DataRequired()])
    submit = SubmitField('註冊')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('電子郵件已註冊。')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用戶名已被使用。')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('舊密碼', validators=[DataRequired()])
    password = PasswordField('新密碼', validators=[
        DataRequired(), EqualTo('password2', message='密碼必須相同。')])
    password2 = PasswordField('確認新密碼',
                              validators=[DataRequired()])
    submit = SubmitField('更新密碼')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('信箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    submit = SubmitField('重設密碼')


class PasswordResetForm(FlaskForm):
    password = PasswordField('新密碼', validators=[
        DataRequired(), EqualTo('password2', message='密碼必須相同。')])
    password2 = PasswordField('確認新密碼', validators=[DataRequired()])
    submit = SubmitField('重設密碼')


class ChangeEmailForm(FlaskForm):
    email = StringField('新信箱', validators=[DataRequired(), Length(1, 64),
                                                 Email()])
    password = PasswordField('密碼', validators=[DataRequired()])
    submit = SubmitField('更新電子郵件地址')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('電子郵件已註冊。')
