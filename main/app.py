from flask import Flask, current_app, jsonify, session, request, redirect, url_for, Blueprint,g,abort
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from flask_login import LoginManager, login_required,login_user,logout_user,current_user
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
from flask_migrate import Migrate

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
        
        login_user(user)
        print(current_user.email)

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
    if request.method=="GET":
        users=User.query.all()
        return jsonify({"message":[user.email for user in users ]})
    
@user_bp.route("/update/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    """
    Updates the user data based on the provided user ID.
    Allows updating email, password, and roles.
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No data provided"}), 400

    # Fetch the user from the database
    user = User.query.get(user_id)                 
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Update email if provided
    new_email = data.get("email")
    if new_email:
        if User.query.filter_by(email=new_email).first() and user.email != new_email:
            return jsonify({"message": "Email already in use"}), 400
        user.email = new_email

    # Update password if provided
    new_password = data.get("password")
    if new_password:
        user.password = generate_password_hash(new_password)

    # Update roles if provided
    new_roles = data.get("role")
    if new_roles:
        user_roles_list = []
        for role_name in new_roles:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                return jsonify({"message": f"Invalid role: {role_name}"}), 400
            user_roles_list.append(role)
        user.role = user_roles_list  # Update the roles relationship

    # Commit changes to the database
    try:
        db.session.commit()
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error updating user: {str(e)}"}), 500


@user_bp.route("/logout", methods=["GET"])
@login_required
def logout():
    if current_user.is_authenticated:
        print(f"Logged in user after logout: {current_user.email}")
    else:
        print("No user is currently logged in after logout.")
    logout_user()
    return jsonify({"message": "User logged out successfully "}), 200

@user_bp.route("/delete/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error deleting user: {str(e)}"}), 500

@role_bp.route("/admin")
@login_required
def admin_dashboard():
    print(current_user.email)
    if current_user.is_authenticated:
        if "Admin" not in [role.name for role in current_user.role]:
            return jsonify({"message": "You do not have permission to access this page"}), 403

        user_email_dict = {} 
        role=Role.query.all()
        for roles in role:
            user_email_dict[roles.name] = []
        for user_role in db.session.query(user_roles):
            user = User.query.get(user_role.user_id)  
            role = Role.query.get(user_role.role_id)  
            if user:  
                    user_email_dict[role.name].append(user.email)
            print(user_email_dict)
        return jsonify({'message':user_email_dict})

# debugging 
@user_bp.before_request
@role_bp.before_request
def log_request_info():
    print(f"Current User: {current_user}")
    print(f"Is Authenticated: {current_user.is_authenticated}")

@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.filter_by(fs_uniquifier=user_id).first()
        print(f"Loading user: {user.email if user else 'No user found'}")
        return user
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

@role_bp.route("/role",methods=["GET","POST"])
@login_required
def role():
    if request.method=="POST":
        data=request.get_json()
        name=data.get("role")
        if not name:
            return jsonify({"message":"role field is required"})
        if name:
            for names in name:
                role=Role.query.filter_by(name=names).first() 
                if not role:
                    roles=Role(name=names)
                    db.session.add(roles)
                    db.session.commit()
                    return jsonify({"message":"Role added succesfully"}),200
                else:
                    return jsonify({"message":"Role already exist"}),400
    else:
        return jsonify({"message":[role.name for role in Role.query.all()]})

@role_bp.route("/assign/<int:id>",methods=["POST"])
@login_required
def assign(id):
    if current_user.is_authenticated:
        user=User.query.get(id)
        if user:
            if "Admin" not in user.role:
                return jsonify({"message":"you dont have permission"}),401
            else:
                    data=request.get_json()
                    role=data.get('role')
                    list=[]
                    for roles in role:
                        print(roles)
                        old_role=Role.query.filter_by(name=roles).first()
                        print(old_role)
                        if old_role:
                            list.append(old_role)
                    user.role=list
                    db.session.commit()
                    return jsonify({"message":"role assigned successfully"})
        return jsonify({"message":"user not in the database"})    
    return jsonify({"message":"User unauthenticated"}),401
    