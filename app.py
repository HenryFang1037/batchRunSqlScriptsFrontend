from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from pymongo import MongoClient
from werkzeug.security import generate_password_hash

from config import Config
from forms import DEPARTMENTS
from models import db, User, Department

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = 'test'

# 初始化SQL数据库
db.init_app(app)
migrate = Migrate(app, db)

# 初始化MongoDB
mongo = MongoClient(app.config['MONGO_URI'])
task_db = mongo.taskdb

# 登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 创建初始管理员
with app.app_context():
    db.drop_all()
    db.create_all()
    for department in DEPARTMENTS:
        dep = Department(name=department[0], code=department[1])
        db.session.add(dep)
    db.session.commit()
    admin_dept = Department.query.filter_by(name='系统管理部').first()
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash(password='admin54321', method='pbkdf2:sha256')
        admin = User(username='admin', email='admin@example.com', password_hash=hashed_pw,
                     role='admin', department_id=admin_dept.id, approved=True)
        db.session.add(admin)
        db.session.commit()

# 注册蓝图
from routes import main as main_blueprint

app.register_blueprint(main_blueprint)

if __name__ == '__main__':
    app.run(debug=True)
