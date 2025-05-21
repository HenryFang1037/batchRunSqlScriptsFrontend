from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, DateTimeField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length

from models import Department, Bank, Model

DEPARTMENTS = [('统计与风险监测处', 'statistic_depart'), ('科技监管处', 'technology_depart'),
               ('普惠金融处', 'inclusive-finance_depart'), ('银行机构检查处', 'bank-audit_depart'),
               ('打击非法金融活动处', 'anti-illegal_depart'), ('非银检查处', 'non-bank-audit_depart'),
               ('大型银行监管处', 'state-bank_depart'), ('股份制和城市商业银行监管处', 'city-bank_depart'),
               ('农村中小银行监管处', 'rural-bank_depart'), ('财产保险监管处', 'property-insurance_depart'),
               ('人身保险监管处', 'life-insurance_depart'), ('非银机构监管处', 'non-bank-regulator_depart'),
               ('金融消费者保护处', 'consumer-protect_depart'), ('海东金融监管分局', 'haidong_depart'),
               ('玉树金融监管分局', 'yushu_depart'), ('果洛金融监管分局', 'guoluo_depart'),
               ('海西金融监管分局', 'haixi_depart'), ('海北金融监管分局', 'haibei_depart'),
               ('黄南金融监管分局', 'huangnan_depart'), ('海南金融监管分局', 'hainan_depart'),
               ('系统管理部', 'admin')]


class RegistrationForm(FlaskForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 动态加载部门选项
        self.department.choices = [
            (dpt.id, dpt.name)
            for dpt in Department.query.order_by('name')
        ]

    department = SelectField('部门', coerce=int, validators=[DataRequired()])
    username = StringField('用户名', validators=[DataRequired()])
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('注册')


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')


class TaskForm(FlaskForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bank_name.choices = [
            (bank.id, bank.name)
            for bank in Bank.query.order_by('id')
        ]
        self.model_name.choices = [
            (model.id, model.name)
            for model in Model.query.order_by('id')
        ]

    bank_name = SelectField('银行名称', coerce=int, validators=[DataRequired()])
    model_name = SelectField('模型组名称', coerce=int, validators=[DataRequired()])
    query_date = DateTimeField('查询日期', format='%Y-%m-%d', validators=[DataRequired()])
    exec_time = DateTimeField('执行时间', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    submit = SubmitField('创建任务')


class DetailForm(FlaskForm):
    pass


class ModelForm(FlaskForm):
    model_name = StringField('模型名称', validators=[DataRequired()])
    description = TextAreaField('模型描述')
    model_file = FileField('模型文件', validators=[
        FileAllowed(['xlsx', 'csv'], '仅支持模型格式文件')
    ])
    # version = StringField('版本号', validators=[DataRequired()])
    submit = SubmitField('上传模型')
