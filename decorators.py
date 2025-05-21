from functools import wraps

from flask import abort, redirect, url_for
from flask_login import current_user


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed = current_user.is_authenticated and \
                  (current_user.role == 'manager' or current_user.role == 'admin')
        if not allowed:
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def anonymous_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('main.tasks'))
        return f(*args, **kwargs)

    return decorated_function
