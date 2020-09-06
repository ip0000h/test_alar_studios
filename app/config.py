import os

DEBUG = True

CSRF_ENABLED = False

CSRF_SESSION_KEY = os.environ.get('CSRF_SESSION_KEY', "secret")

SECRET_KEY = os.environ.get('SECRET_KEY', "secret")

DB_API_URI = os.environ['DATABASE_URI']
