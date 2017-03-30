# -*- coding: utf-8 -*-
from os.path import abspath, dirname, join


_cwd = dirname(abspath(__file__))


class BaseConfiguration(object):
    """This is the applications base configuration object.
    It will contain all of the DEFAULT constant values for
    our applications.  Every configuration object will inherit
    this.

    """

    DEBUG = True

    DATABASE = 'app.db'
    DATABASE_PATH = join(_cwd, DATABASE)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_PATH
    DEBUG_COUNT = 5000


class DevConfiguration(BaseConfiguration):
    """This configuration should be used and tailored to help
    limit the frustrations of debugging

    {{ params }}
    DEBUG = False"""


    DATABASE = 'dev.db'
    DATABASE_PATH = join(_cwd, DATABASE)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_PATH
    DEBUG = False


class TestingConfiguration(BaseConfiguration):
    """This configuration should be used and tailored for testing
    the application.

    {{ params }}
    TESTING = True"""
    TESTING = True
    DATABASE = 'tests_auth.db'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
