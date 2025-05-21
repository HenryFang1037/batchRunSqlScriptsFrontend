import io
import json
import os
from datetime import datetime, timedelta

import jwt
import pandas as pd
import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash

from decorators import admin_required, manager_required
from forms import LoginForm, TaskForm
from forms import ModelForm, RegistrationForm
from models import db, User, Department, Bank

main = Blueprint('main', __name__)

FASTAPI_URL = os.environ.get("FASTAPI_URL", "http://127.0.0.1")
SECRET_KEY = os.environ.get("SECRET_KEY", 'test')


# 公共路由
@main.route('/')
def index():
    return redirect(url_for('main.login'))


# 登录路由
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.tasks_panel'))

    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data) and user.approved:
            token = jwt.encode({
                'user_id': user.id,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(hours=1)  # 过期时间1小时
            },
                SECRET_KEY,
                algorithm='HS256')
            login_user(user)
            response = redirect(url_for('main.tasks_panel'))
            response.set_cookie('access_token', token, httponly=True, secure=True)
            return response
        flash('无效的用户名或密码', 'error')

    return render_template('login.html', form=form)


# 注册路由
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                # 获取部门实例
                dept = Department.query.get(form.department.data)
                if not dept:
                    flash('无效的部门选择', 'danger')
                    return redirect(url_for('main.register'))
                if User.query.get(form.username.data):
                    flash('该用户名已被注册', 'error')
                    return redirect(url_for('main.register'))
                if User.query.get(form.email.data):
                    flash('该邮箱已被注册', 'error')
                    return redirect(url_for('main.register'))
                new_user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password_hash=generate_password_hash(password=form.password.data, method='pbkdf2:sha256'),
                    department_id=dept.id,  # 正确赋值部门ID
                    role='user',
                    approved=False
                )
                db.session.add(new_user)
                db.session.commit()

                flash('注册成功，等待审核', 'success')
                print('注册成功，等待审核', 'success')
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                flash('注册失败，请稍后重试', 'error')
        flash('注册失败，请检查输入的用户名、邮箱或密码', 'error')

    return render_template('register.html', form=form)


# 登出路由
@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


# 任务相关路由
@main.route('/tasks', methods=['GET'])
@login_required
def tasks_panel():
    # tasks 获取可使用缓存机制进行优化获取逻辑，优先考虑redis
    tasks = []
    form = TaskForm()
    if current_user.role == 'admin':
        query = {}
    else:
        query = {'department': current_user.department}
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(f'{FASTAPI_URL}/get_tasks', headers=headers, data=json.dumps(query))
        if response.status_code == 200:
            tasks = response.json()
    except Exception as e:
        flash(f"获取任务列表失败：{e}", 'error')

    return render_template('tasks.html', tasks=tasks, form=form)


@main.route('/tasks/add_task', methods=['POST'])
@login_required
def add_task():
    form = TaskForm()
    if form.validate_on_submit():
        new_task = {
            "bank_name": form.bank_name.data,
            "model_name": form.model_name.data,
            "query_date": form.query_date.data,
            "exec_time": form.exec_time.data,
            "department": current_user.department,
            "creator": current_user.username
        }
        # 向后端FastApi服务发送post请求
        token = request.cookies.get('access_token')
        if token:
            headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
            try:
                response = requests.post(f"{FASTAPI_URL}/create_task", headers=headers, data=json.dumps(new_task))
                if response.status_code == 200:
                    flash('任务已成功提交', 'success')

            except Exception as e:
                flash(f"任务创建失败:{e}", 'error')

    return redirect(url_for('main.tasks_panel'))


@main.route('/tasks/delete_task', methods=['POST'])
@login_required
@manager_required
def delete_task():
    if request.method == 'POST' and request.form.get('task_id', None) is not None:
        token = request.cookies.get('access_token')
        if token:
            headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
            try:
                task_id = int(request.form.get('task_id'))
                response = requests.post(f"{FASTAPI_URL}/delete_task", headers=headers,
                                         data=json.dumps({'task_id': task_id}))
                if response.status_code == 200:
                    flash('任务删除成功', 'success')
            except Exception as e:
                flash(f'任务删除失败:{e}', 'error')
    return redirect(url_for('main.tasks_panel'))


@main.route('/details', methods=['GET'])
@login_required
def task_details_panel():
    task_details = []
    if current_user.role == 'admin':
        query = {}
    else:
        query = {'department': current_user.department}
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(f'{FASTAPI_URL}/get_details', headers=headers, data=json.dumps(query))
        if response.status_code == 200:
            main_tasks = response.json()
            latest_task_id = sorted(main_tasks, key=lambda x: x['exec_time'], reverse=True)[0]['task_id']
            response = requests.post(f"{FASTAPI_URL}/get_details", headers=headers,
                                     data=json.dumps({'task_id': latest_task_id}))
            if response.status_code == 200:
                task_details = response.json()
            else:
                flash(f"获取主任务编号{latest_task_id}执行详情失败", 'error')
        else:
            flash("获取主任务信息失败", 'error')
    except Exception as e:
        flash(f"获取主任务执行详情失败: {e}", "error")

    return render_template('details.html', task_details=task_details)


@main.route('/details', methods=['POST'])
@login_required
def get_task_details():
    task_details = []
    task_id = request.form.get('task_id', None)
    if request.method == 'POST' and task_id is not None:
        try:
            headers = {'Content-Type': 'application/json'}
            task_details = requests.post(f"{FASTAPI_URL}/get_details", headers=headers,
                                         data=json.dumps({'task_id': task_id}))
            if task_details.status_code == 200:
                task_details = task_details.json()
        except Exception as e:
            flash(f'获取任务执行明细失败:{e}', 'error')
    else:
        flash("获取任务执行明细失败", 'error')

    return render_template('details.html', task_details=task_details)


@main.route('/details/download', methods=['POST'])
@login_required
def download_task_details():
    task_id = request.form.get('task_id', None)
    if request.method == 'POST' and task_id is not None:
        try:
            headers = {'Content-Type': 'application/json'}
            task_details = requests.post(f"{FASTAPI_URL}/down_details", headers=headers,
                                         data=json.dumps({'task_id': task_id}))
            if task_details.status_code == 200:
                task_details = task_details.json()
                data = pd.DataFrame(task_details)
                bank_name = data.iloc[0]['银行机构']
                # 生成内存中的 Excel 文件
                buffer = io.BytesIO()
                with pd.ExcelWriter(buffer) as writer:
                    data.to_excel(writer, index=False)
                buffer.seek(0)

                return send_file(
                    buffer,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True,
                    download_name=f'{bank_name}_statistics.xlsx'
                )
        except Exception as e:
            flash(f'下载任务执行明细失败:{e}', 'error')
    else:
        flash("下载任务执行明细失败", 'error')
    return redirect(url_for('main.task_details_panel'))


@main.route('/records', methods=['POST', 'GET'])
@login_required
def records_panel():
    records = []

    if request.method == 'POST':
        task_id = request.form['task_id']
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f'{FASTAPI_URL}/get_records', headers=headers,
                                     data=json.dumps({'task_id': task_id}))
            if response.status_code == 200:
                records = response.json()
            else:
                flash(f"获取表数据失败", 'error')

        except Exception as e:
            flash(f"获取表数据失败: {e}", "error")

    return render_template('download.html', records=records)


@main.route('/records/export/<int:task_id>/<bank>/<table>')
@login_required
def download_records(task_id, bank, table):
    if task_id and bank and table:
        try:
            headers = {'Content-Type': 'application/json'}
            data = {'task_id': task_id, 'bank_name': bank, 'table_name': table}
            response = requests.post(f'{FASTAPI_URL}/download_records', headers=headers, data=json.dumps(data))
            if response.status_code == 200:
                records = pd.DataFrame(response.json())
                # 生成内存中的 Excel 文件
                buffer = io.BytesIO()
                with pd.ExcelWriter(buffer) as writer:
                    records.to_excel(writer, index=False)
                buffer.seek(0)

                return send_file(
                    buffer,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True,
                    download_name=f'{bank}_{table}_detail.xlsx'
                )
        except Exception as e:
            flash(f'下载明细数据失败:{e}', 'error')
    else:
        flash("下载明细数据失败，请检查任务ID、银行名称或表名称", 'error')

    return redirect(url_for('main.records_panel'))


@main.route('/models', methods=['GET'])
@login_required
def models_panel():
    models = []
    form = ModelForm()
    # 管理员可查看所有部门
    if current_user.role == 'admin':
        query = {}
    else:
        query = {"department": current_user.department}
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(f"{FASTAPI_URL}/get_models", headers=headers, data=json.dumps(query))
        if response.status_code == 200:
            models = response.json()
        else:
            flash("获取模型信息失败", 'error')
    except Exception as e:
        flash(f"获取模型信息失败:{e}", 'error')

    return render_template('models.html', models=models, form=form)


@main.route('/models/add_model', methods=['POST'])
@login_required
@manager_required
def add_model():
    form = ModelForm()
    if form.validate_on_submit():
        file = pd.read_excel(form.model_file)
        data = {
            "name": form.model_name.data,
            "description": form.description.data,
            "creator": current_user.username,
            "department": current_user.department,
            "created_time": datetime.now()
        }
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer) as writer:
            file.to_excel(writer, index=False)
        buffer.seek(0)
        # 向FASTAPI后端发送请求
        files = {
            "file": ("model_data.xlsx", buffer, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        response = requests.post(f"{FASTAPI_URL}/add_model", files=files, data=json.dumps(data))
        buffer.close()
        if response.status_code == 200:
            flash('模型上传成功', 'success')
            return render_template('models.html', form=form)
    else:
        flash('模型上传失败', 'error')

    return redirect(url_for('main.models_panel'))


@main.route('/admin')
@login_required
@admin_required
def admin():
    return render_template('audit.html')


@main.route('/admin/audit')
@login_required
@admin_required
def audit_panel():
    pending_users = User.query.filter_by(approved=False).all()
    return render_template('audit.html',
                           pending_users=pending_users)


@main.route('/admin/audit/approve_user/<int:user_id>')
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    flash(f'用户 {user.username} 已通过审核', 'success')
    return redirect(url_for('main.audit_panel'))


@main.route('/admin/users')
@login_required
@admin_required
def user_panel():
    all_users = User.query.all()
    departments = Department.query.all()
    return render_template('users.html', all_users=all_users, departments=departments)


@main.route('/admin/users/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    print(user_id)
    try:
        user = User.query.get(user_id)
        print(user.username)
        if user:
            db.session.delete(user)
            # User.query.delete(user_id)
            db.session.commit()
            flash(f'用户 {user.username} 已被删除', 'success')
    except Exception as e:
        flash(f"删除用户失败:{e}", 'error')

    return redirect(url_for('main.user_panel'))


@main.route('/admin/users/edit_user', methods=["POST"])
@login_required
@admin_required
def edit_user():
    user_id = request.form['user_id']
    depart_name = request.form['department']
    department = Department.query.filter_by(name=depart_name).first()
    role = request.form['role']
    print('depart', department.name, user_id, role)
    try:
        user = User.query.get(user_id)
        if user:
            user.role = role
            user.department_id = department.id
            db.session.commit()
            flash(f'用户 {user.username} 属性已修改', 'success')
    except Exception as e:
        flash(f"修改用户信息失败:{e}", 'error')

    return redirect(url_for('main.user_panel'))


@main.route('/admin/departments')
@login_required
@admin_required
def departments_panel():
    departments = Department.query.order_by(Department.name).all()
    return render_template('departments.html', departments=departments)


@main.route('/admin/departments/add_department', methods=['POST'])
@login_required
@admin_required
def add_department():
    name = request.form['name']
    code = request.form['code']
    try:
        if Department.query.filter_by(name=name).first() or Department.query.filter_by(code=code).first():
            flash("该部门名称或部门代码已存在", 'error')
        else:
            new_department = Department(name=name, code=code)
            db.session.add(new_department)
            db.session.commit()
    except Exception as e:
        flash(f"新增部门信息失败:{e}", 'error')

    return redirect(url_for('main.departments_panel'))


@main.route('/admin/departments/delete_department/<int:dept_id>')
@login_required
@admin_required
def delete_department(dept_id):
    try:
        department = Department.query.get(dept_id)
        if not department:
            flash("该部门ID不存在", 'error')
        else:
            db.session.delete(department)
            db.session.commit()
    except Exception as e:
        flash(f"删除部门失败:{e}", 'error')

    return redirect(url_for('main.departments_panel'))


@main.route('/admin/banks')
@login_required
@admin_required
def banks_panel():
    banks = Bank.query.order_by(Bank.name).all()
    return render_template('banks.html', banks=banks)


@main.route('/admin/banks/add_bank', methods=['POST'])
@login_required
@admin_required
def add_bank():
    bank = request.form['name']
    dbname = request.form['dbname']
    try:
        if Bank.query.filter_by(name=bank).first() or Bank.query.filter_by(dbname=dbname).first():
            flash("该银行名称或对应的数据库名称已存在", 'error')
        else:
            new_bank = Bank(name=bank, dbname=dbname)
            db.session.add(new_bank)
            db.session.commit()
    except Exception as e:
        flash(f"新增银行信息失败:{e}", 'error')

    return redirect(url_for('main.banks_panel'))


@main.route('/admin/banks/delete_bank/<int:bank_id>')
@login_required
@admin_required
def delete_bank(bank_id):
    try:
        bank = Bank.query.get(bank_id)
        if not bank:
            flash("该银行ID不存在", 'error')
        else:
            db.session.delete(bank)
            db.session.commit()
    except Exception as e:
        flash(f"删除银行失败:{e}", 'error')

    return redirect(url_for('main.banks_panel'))

