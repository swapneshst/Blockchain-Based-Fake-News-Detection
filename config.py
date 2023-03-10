import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'no-not-again'
	DEBUG = os.environ.get('DEBUG') or 1