from flask import Flask, jsonify, session, request, redirect, url_for, Blueprint,g
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from flask_login import LoginManager,login_user,logout_user,current_user
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
from flask_migrate import Migrate
from flask_security import roles_accepted

# Database Initialization
db = SQLAlchemy()
login_manager=LoginManager()
migrate=Migrate()
user_bp = Blueprint('user', __name__,url_prefix="/auth")
role_bp=Blueprint('role',__name__)

#  Association table for many-to-many relationship between User and Role
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.role_id'), primary_key=True)
)

class User(db.Model,UserMixin):
    __tablename__="user"
    id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    email=db.Column(db.String(250),unique=True)
    password=db.Column(db.String(250),nullable=False,server_default="")
    active = db.Column(db.Boolean(),default=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'), nullable=True)
    role = db.relationship('Role', back_populates='users',secondary=user_roles )
    fs_uniquifier = db.Column(db.String(255),unique=True,nullable=False,default=lambda: str(uuid.uuid4()))

    def __ref__(self):
        return f"id is {id}"
    
class Role(db.Model,RoleMixin):
    __tablename__="role"
    role_id=db.Column(db.Integer,autoincrement=True,primary_key=True)
    name=db.Column(db.String(250),unique=True,nullable=False)
    users = db.relationship('User', back_populates='role',secondary=user_roles,lazy=True)


def create_roles():
        existing_roles = {role.name for role in Role.query.all()}  # Fetch existing roles from the database
        roles_to_add = [
            Role(role_id=1, name='Admin'),
            Role(role_id=2, name='Teacher'),
            Role(role_id=3, name='Staff'),
            Role(role_id=4, name='Student'),
        ]

        new_roles = [role for role in roles_to_add if role.name not in existing_roles]

        if new_roles:  # Only add roles if they're not already in the database
            db.session.add_all(new_roles)
            db.session.commit()
            print(f"Roles created successfully: {[role.name for role in new_roles]}")
        else:
            print("Roles already exist, no new roles were added.")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@user_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        
        # First, validate input
        if not email or not password:
            return jsonify({"message": "email and password required"}), 400
        
        # Find the user
        user = User.query.filter_by(email=email).first()
        
        # Check if user exists and password is correct
        if not user or not check_password_hash(user.password, password):
            return jsonify({"message": "Incorrect email or password"}), 401
        
        # Login the user
        login_user(user)
        
        return jsonify({
            'message': 'Login Success', 
        }), 200
    
    return jsonify({"message": "login end-point is available"})

@user_bp.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        create_roles()
        data=request.get_json()
        email=data.get("email")
        password=data.get("password")
        role=data.get("role",[])
        if not (email and password and role):
                return jsonify({"message":"email, password and role are required!"}),400
        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({"message":"user already exist"})
        user_roles_list = []
        for role_name in role:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                return jsonify({"message": f"Invalid role: {role_name}"}), 400
            user_roles_list.append(role)
        user=User(email=email,password=generate_password_hash(password),role=user_roles_list)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message":" registered successfully!"}),201
    return jsonify({"message":" registration end-point is available, sent POST request"})

@user_bp.route("/logout", methods=["GET"])
def logout():
    logout_user()
    return jsonify({"message": "User logged out successfully"}), 200

@role_bp.route("/admin")
@roles_accepted("Admin")
def admin_dashboard():
    teachers = []
    admin = []
    staffs = []
    students = []
    
    # Query for role-specific users
    for user_role in db.session.query(user_roles):
        user = User.query.get(user_role.user_id)
        if user_role.role_id == 1:
            admin.append(user)
        elif user_role.role_id == 2:
            teachers.append(user)
        elif user_role.role_id == 3:
            staffs.append(user)
        elif user_role.role_id == 4:
            students.append(user)
    
    return jsonify({
        "Admin": [user.email for user in admin],
        "Teacher": [user.email for user in teachers],
        "Staff": [user.email for user in staffs],
        "Student": [user.email for user in students],
    }), 200

