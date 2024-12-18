from datetime import timedelta
from flask import Flask
import os
from .app import db,user_bp,role_bp,login_manager,migrate
from .secret import secret
# The __init__.py serves double duty: it will contain the application factory, and it tells Python that the flaskr directory 
# should be treated as a package.

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=secret,
        SESSION_TYPE='filesystem',
        REMEMBER_COOKIE_DURATION = timedelta(days=14),
        PERMANENT_SESSION_LIFETIME= timedelta(days=14),
        SESSION_PERMANENT = True,

        SQLALCHEMY_DATABASE_URI="sqlite:///db.sqlites",
        DATABASE=os.path.join(app.instance_path, 'FLASK_SQLALCHEMY.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    migrate.init_app(app,db)
    login_manager.init_app(app)    
    app.register_blueprint(user_bp)
    app.register_blueprint(role_bp)
    app.add_url_rule('/',endpoint='index')

    return app
    
