import asyncio
import enum
import hashlib
import logging
import os
from functools import wraps

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientConnectorError, ClientResponseError
from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, session as fsession, url_for)
from sqlalchemy import (Column, Enum, Integer, String,
                       create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


# maximum timeout for async json view
TIMEOUT_MAX = 2
# urls for async json view
DATA_URLS = [
    'http://json:8000/first_data.json',
    'http://json:8000/second_data.json',
    'http://json:8000/third_data.json',
]

# create an engine and session for sqlalchemy
engine = create_engine(os.environ.get('DATABASE_URI'))
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

# create a flask app and upload config
app = Flask(__name__)
app.config.from_object('config')

# event loop for async json view
loop = asyncio.get_event_loop()


class UserRole(enum.Enum):
    """
    For regular user - only read access
    For admin user - add/change/delete users
    """
    regular = 1
    admin = 2


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.regular)

    def as_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role.name
        }


async def fetch(url, session):
    """Get data from url"""
    try:
        async with session.get(url) as response:
            if response.status != 200:
                return []
            return await response.json()
    except (ClientConnectorError, ClientResponseError):
        return []


def sort_results(responses):
    """For sorting json results by id"""
    return sorted(sum(responses, []), key=lambda el: el['id'])


async def get_data():
    """Get data asynchronously from 3 endponts"""
    async with ClientSession(timeout=ClientTimeout(total=2)) as session:
        responses = await asyncio.gather(
            fetch(DATA_URLS[0], session),
            fetch(DATA_URLS[1], session),
            fetch(DATA_URLS[2], session),
        )
    return sort_results(responses)


def login_required(f):
    """Decorator for pages with login authentication requirement"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not fsession.get('is_logged'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator for pages with admin authentication requirement"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if fsession.get('user_role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def crypt_password(password):
    return hashlib.sha512(password.encode('utf-8')).hexdigest()


@app.route('/')
@login_required
def index():
    users = session.query(User).all()
    return render_template(
        'index.html',
        users=[user.as_dict() for user in users],
        role_admin=(fsession['user_role'] == 'admin')
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = session.query(User).filter_by(username=username).first()
        if user and user.password == crypt_password(password):
            fsession['is_logged'] = True
            fsession['user_id'] = user.id
            fsession['user_role'] = user.role.name
            return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    fsession['is_logged'] = False
    fsession['user_id'] = None
    fsession['user_role'] = None
    return redirect(url_for('login'))


@app.route('/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.form
    try:
        new_user = User(
            username=data['username'],
            password=crypt_password(data['password']),
            role=data['role']
        )
        session.add(new_user)
        session.commit()
        return jsonify(new_user.as_dict())
    except Exception as e:
        logging.error(e)
        session.rollback()


@app.route('/edit_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    data = request.form
    try:
        user = session.query(User).get(user_id)
        user.username = data['username']
        # user.password = crypt_password(data['password'])
        user.role = data['role']
        if not user:
            abort(404)
        session.commit()
        return jsonify(user.as_dict())
    except Exception as e:
        logging.error(e)
        session.rollback()


@app.route('/delete_user/<user_id>', methods=['GET'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = session.query(User).get(user_id)
        if not user:
            abort(404)
        session.delete(user)
        session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logging.error(e)
        session.rollback()


@app.route('/json_async')
def json_async():
    result = loop.run_until_complete(get_data())
    return jsonify(result)


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    # create default admin user for testing
    admin_user = session.query(User).filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            role='admin',
            password=crypt_password('admin')
        )
        session.add(admin_user)
        session.commit()
    # create default regular user for testing
    regular_user = session.query(User).filter_by(username='regular').first()
    if not regular_user:
        regular_user = User(
            username='regular',
            role='regular',
            password=crypt_password('regular')
        )
        session.add(regular_user)
        session.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)
