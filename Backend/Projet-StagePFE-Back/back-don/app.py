from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required, get_jwt_identity
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

from enum import Enum
from flask_cors import CORS
import ast
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask import url_for
from flask import send_from_directory
from datetime import datetime
from datetime import date


app = Flask(__name__)

CORS(app, resources={r"/*": {
    "origins": ["http://localhost:4200", "http://localhost:8100"],
    "allow_headers": ["Content-Type", "Authorization"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}})



# Database Configuration and token
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres123@localhost:5432/gestiondonsdb?client_encoding=utf8'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = '473f7e8c82ad4f2aae3704006097205f'
# for  images 
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# for email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lobnadrira21@gmail.com'
app.config['MAIL_PASSWORD'] = 'afyw aypt zoqx mrvj'
app.config['MAIL_DEFAULT_SENDER'] = 'DonByUIB <admin@donbyuib.tn>'

mail = Mail(app)  







# Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db) 
jwt = JWTManager(app)

revoked_tokens = set()




# ------------------- MODELS -------------------

# User Model (Admin or Donator or Association)
class User(db.Model):
    """ General User model for Admin, Donator, and Associations """
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'donator'

    # Donator-specific attributes
    nom_complet = db.Column(db.String(80), nullable=True)  # Only for donators
    telephone = db.Column(db.String(15), nullable=True)    # Only for donators
    token = db.Column(db.String(255), nullable=True)       # JWT token storage if needed

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)




class Association(db.Model):
    __tablename__ = 'associations'  

    id_association = db.Column(db.Integer, primary_key=True)
    nom_complet = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    description_association = db.Column(db.String(255), nullable=True)
    telephone = db.Column(db.String(15), nullable=False)  
    adresse = db.Column(db.String(100), nullable=True)  
    type_association = db.Column(db.String(50), nullable=True)
    photo = db.Column(db.String(255), nullable=True)  # pour stocker le chemin de la photo

    
    # association créé par Admin
    id_admin = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False) 

    def __repr__(self):
        return f"<Association {self.nom_complet}>"

class Don(db.Model):
    __tablename__ = "dons"

    id_don = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(600), nullable=True)
    objectif = db.Column(db.Float, nullable=False)
    montant_collecte = db.Column(db.Float, default=0.0)
    date_fin_collecte = db.Column(db.Date, nullable=False)
    recu_don = db.Column(db.String(255), nullable=True)
    photo_don = db.Column(db.String(255), nullable=True)
    statut = db.Column(db.String(20), default="en_attente")  # "en_attente", "valide", "refuse"

     #  Attributs utiles pour les statistiques :
    nb_donateurs = db.Column(db.Integer, default=0)
    is_reussi = db.Column(db.Boolean, default=False)
    

    # clé etrangere avec cascade
    id_association = db.Column(
        db.Integer,
        db.ForeignKey("associations.id_association", ondelete="CASCADE"),
        nullable=False
    )
    association = db.relationship("Association", backref=db.backref("dons", cascade="all, delete-orphan"))

    id_utilisateur = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
class Participation(db.Model):
    __tablename__ = "participations"

    id_participation = db.Column(db.Integer, primary_key=True)
    montant = db.Column(db.Float, nullable=False)
    date_participation = db.Column(db.DateTime, default=datetime.utcnow)

    # Clé étrangère vers le don
    id_don = db.Column(db.Integer, db.ForeignKey("dons.id_don", ondelete="CASCADE"), nullable=False)
    don = db.relationship("Don", backref=db.backref("participations", cascade="all, delete-orphan"))

    # Clé étrangère vers l’utilisateur (donateur)
    id_user = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User", backref=db.backref("participations", cascade="all, delete-orphan"))


class Publication(db.Model):
    __tablename__ = "publications"

    id_publication = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(100), nullable=False)
    contenu = db.Column(db.Text, nullable=False)
    date_publication = db.Column(db.Date, nullable=False)
    nb_likes = db.Column(db.Integer, default=0)
    nb_commentaires = db.Column(db.Integer, default=0)
    nb_partages = db.Column(db.Integer, default=0)
    statut = db.Column(db.String(20), default="en_attente")  # "en_attente", "valide", "refuse"

    # clé etrangére avec CASCADE (si une association a été supprimée, ses publications seront supprimées)
    id_association = db.Column(
        db.Integer,
        db.ForeignKey("associations.id_association", ondelete="CASCADE"),
        nullable=False
    )

    # la liaison d'une publication avec les commentaires
    commentaires = db.relationship("Commentaire", backref="publication", cascade="all, delete-orphan")
    association = db.relationship("Association", backref="publications")

class Commentaire(db.Model):
    __tablename__ = "commentaires"

    id_commentaire = db.Column(db.Integer, primary_key=True)
    contenu = db.Column(db.Text, nullable=False)
    date_commentaire = db.Column(db.Date, nullable=False)
    sentiment = db.Column(db.String(20), nullable=True)  # "positif", "neutre", "négatif"


    # clé etrangére avec CASCADE (si une publication a été supprimée, ses commentaires seront supprimées)
    id_publication = db.Column(
        db.Integer,
        db.ForeignKey("publications.id_publication", ondelete="CASCADE"),
        nullable=False
    )
    id_user = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)



class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    contenu = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    id_association = db.Column(db.Integer, db.ForeignKey("associations.id_association", ondelete="CASCADE"), nullable=False)
    id_publication = db.Column(db.Integer, db.ForeignKey("publications.id_publication", ondelete="CASCADE"), nullable=True)
    id_don = db.Column(db.Integer, db.ForeignKey("dons.id_don", ondelete="CASCADE"), nullable=True)  # ✅ AJOUTÉ ICI

    association = db.relationship("Association", backref=db.backref("notifications", lazy=True, cascade="all, delete-orphan"))
    publication = db.relationship("Publication", backref=db.backref("notifications", lazy=True, cascade="all, delete-orphan"))
    don = db.relationship("Don", backref=db.backref("notifications", lazy=True, cascade="all, delete-orphan"))  # ✅ AJOUTÉ ICI

    id_user = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    user = db.relationship("User", backref="notifications")

# ---------- Methods ---------
@app.before_request

def handle_options_request():
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight request successful"})
        origin = request.headers.get("Origin", "*")
        response.headers.add("Access-Control-Allow-Origin", origin)
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response, 200







import re

# Fonction de validation
def is_valid_nom_complet(nom):
     return bool(re.fullmatch(r"[A-Za-zÀ-ÿ\s\-]{1,40}", nom))
def is_valid_email(email):
    # Format basique d’un email
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email))

def is_valid_telephone(tel):
    return bool(re.fullmatch(r"\d{8}", tel))

def is_strong_password(password):
    return bool(re.fullmatch(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$", password))

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    nom_complet = data.get("nom_complet")
    telephone = data.get("telephone")
    role = data.get("role", "donator")

    if not email or not password or not nom_complet or not telephone:
        return jsonify({"error": "All fields are required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "L'email n'est pas valide."}), 400

    if not is_valid_nom_complet(nom_complet):
        return jsonify({"error": "Le nom complet ne doit contenir que des lettres, espaces ou tirets (max 40 caractères)."}), 400

    if not is_valid_telephone(telephone):
        return jsonify({"error": "Le numéro de téléphone doit contenir exactement 8 chiffres."}), 400

    if not is_strong_password(password):
        return jsonify({"error": "Le mot de passe doit contenir au moins une lettre majuscule, un chiffre, et un caractère spécial."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409

    if role not in ["admin", "donator"]:
        return jsonify({"error": "Invalid role"}), 400

    user = User(email=email, role=role, nom_complet=nom_complet, telephone=telephone)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": f"{role.capitalize()} registered successfully"}), 201



# Login Route
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    username = None
    if user.role == "association":
        association = Association.query.filter_by(email=email).first()
        if association:
            username = association.nom_complet  # Get name from Association table
    else:
        username = user.nom_complet

    # Store user.id as identity (must be string or integer)
    additional_claims = {"email": user.email, "role": user.role}
    access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)

    print("Generated JWT:", access_token)  # Debugging

    return jsonify({
        "access_token": access_token,
        "role": user.role,
        "username": user.nom_complet  
    })



@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # Get token identifier (JTI)
    revoked_tokens.add(jti)  # Add token to revoked list
    return jsonify({"message": "Successfully logged out"}), 200

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in revoked_tokens

#reset password 

@app.route("/reset-password", methods=["POST"])
@jwt_required()
def reset_password():
    data = request.get_json()
    new_password = data.get("new_password")

    if not new_password:
        return jsonify({"error": "Mot de passe requis."}), 400

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "Utilisateur non trouvé."}), 404

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Mot de passe réinitialisé avec succès."}), 200







# reset + verification with email
@app.route("/request-password-reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    email = data.get("email")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Aucun compte avec cet email."}), 404

    # Générer token temporaire (valide 30 min)
    token = create_access_token(identity=str(user.id), expires_delta=timedelta(minutes=30))


    reset_link = f"http://localhost:4200/#/reset-password/{token}"


    # Envoyer l'email
    msg = Message("Réinitialisation du mot de passe", sender=app.config['MAIL_USERNAME'], recipients=[email])

    msg.body = f"Bonjour,\n\nCliquez ici pour réinitialiser votre mot de passe : {reset_link}\n\nCe lien expire dans 30 minutes."
    mail.send(msg)

    return jsonify({"message": "Un lien de réinitialisation a été envoyé à votre email."}), 200


@app.route("/create-association", methods=["POST"])
@jwt_required()
def create_association():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()

        if claims.get("role") != "admin":
            return jsonify({"error": "Access denied, admin only!"}), 403

        data = request.get_json()
        print("📥 Data received:", data)

        required_fields = ["nom_complet", "email", "telephone", "adresse", "type_association", "password"]
        for field in required_fields:
            if field not in data or not isinstance(data[field], str) or not data[field].strip():
                return jsonify({"error": f"'{field}' must be a non-empty string"}), 400

        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already exists"}), 409

        # 1. Créer le user
        new_user = User(
            email=data["email"].strip(),
            role="association"
        )
        new_user.set_password(data["password"])
        db.session.add(new_user)
        db.session.flush()  # Pour obtenir new_user.id sans commit

        # 2. Créer l'association liée à ce user
        new_association = Association(
            nom_complet=data["nom_complet"].strip(),
            email=data["email"].strip(),
            description_association=data.get("description_association", "").strip(),
            telephone=data["telephone"].strip(),
            adresse=data["adresse"].strip(),
            type_association=data["type_association"].strip(),
            id_admin=current_user_id  # 🟢 celui qui est loggé (admin)
        )
        db.session.add(new_association)
        db.session.commit()

        return jsonify({"message": "✅ Association created successfully", "user_id": new_user.id}), 201

    except Exception as e:
        db.session.rollback()
        print("🔥 Server Error in /create-association:", str(e))
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500








@app.route("/associations", methods=["GET"])
@jwt_required()
def get_associations():
    current_user_id = get_jwt_identity()
    claims = get_jwt()  # Retrieve claims including role

    if claims.get("role") not in ["admin", "donator"]:
        return jsonify({"error": "Access denied!"}), 403

    try:
        associations = Association.query.all()
        result = [
            {
                "id_association": assoc.id_association,  # ✅ Ensure it's included
                "nom_complet": assoc.nom_complet,  # ✅ Ensure it's included
                "email": assoc.email,  # ✅ Ensure it's included
                "description_association": assoc.description_association,  # ✅ Ensure it's included
                "telephone": assoc.telephone,  # ✅ Ensure it's included
                "adresse": assoc.adresse,  # ✅ Ensure it's included
                "type_association": assoc.type_association, # ✅ Ensure it's included
                
            }
            for assoc in associations
        ]
        return jsonify(result), 200  # ✅ Correct JSON format

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# modifier association par admin 
@app.route("/modify-compte-association/<int:id>", methods=["PUT"])
@jwt_required()
def modify_compte_association(id):
    try:
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Access denied!"}), 403

        data = request.form
        association = Association.query.get(id)
        user = User.query.filter_by(email=association.email).first()

        if not association or not user:
            return jsonify({"error": "Association not found!"}), 404

        # Mise à jour des champs...
        if "nom_complet" in data:
            association.nom_complet = data["nom_complet"].strip()

        if "email" in data:
            existing_user = User.query.filter(User.email == data["email"], User.id != user.id).first()
            if existing_user:
                return jsonify({"error": "Email already exists!"}), 409
            association.email = data["email"].strip()
            user.email = data["email"].strip()

        if "description_association" in data:
            association.description_association = data["description_association"].strip()
        if "telephone" in data:
            association.telephone = data["telephone"].strip()
        if "adresse" in data:
            association.adresse = data["adresse"].strip()
        if "type_association" in data:
            association.type_association = data["type_association"].strip()

        db.session.commit()
        return jsonify({"message": "Association updated successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# supprimer association par l'admin
@app.route("/delete-compte-association/<int:id_association>", methods=["DELETE"])
@jwt_required()
def delete_compte_association(id_association):
    try:
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Access denied! Only admin can delete an association."}), 403

        association = Association.query.get(id_association)
        if not association:
            return jsonify({"error": "Association not found."}), 404

        user = User.query.filter_by(email=association.email).first()

        # Supprimer d'abord l'utilisateur lié (optionnel selon ton modèle)
        if user:
            db.session.delete(user)

        db.session.delete(association)
        db.session.commit()

        return jsonify({"message": "Association deleted successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/modify-profile-association", methods=["PUT"])
@jwt_required()
def modify_association():
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied! Only associations can modify their profile."}), 403

        data = request.form
        file = request.files.get("photo_file")

        association = Association.query.filter_by(email=claims.get("email")).first()
        user = User.query.filter_by(email=claims.get("email")).first()

        if not association or not user:
            return jsonify({"error": "Association not found!"}), 404

        if "nom_complet" in data:
            association.nom_complet = data["nom_complet"].strip()

        if "email" in data:
            existing_user = User.query.filter(User.email == data["email"], User.id != user.id).first()
            if existing_user:
                return jsonify({"error": "Email already exists!"}), 409
            association.email = data["email"].strip()
            user.email = data["email"].strip()

        if "description_association" in data:
            association.description_association = data["description_association"].strip()

        if "telephone" in data:
            association.telephone = data["telephone"].strip()

        if "adresse" in data:
            association.adresse = data["adresse"].strip()

        if "type_association" in data:
            association.type_association = data["type_association"].strip()

        if "old_password" in data and "new_password" in data:
            if not user.check_password(data["old_password"]):
                return jsonify({"error": "Old password is incorrect!"}), 401
            user.password_hash = generate_password_hash(data["new_password"])

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            association.photo = f"/static/uploads/{filename}"

        db.session.commit()
        return jsonify({"message": "Association profile updated successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    
@app.route("/modify-profile-donateur", methods=["PUT"])
@jwt_required()
def modify_donator():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()

        if claims.get("role") != "donator":
            return jsonify({"error": "Access denied! Only donators can modify their profile."}), 403

        data = request.form if request.form else request.json

        # Récupérer l'utilisateur
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "Donator not found!"}), 404

        # Mettre à jour les champs
        if "nom_complet" in data and data["nom_complet"].strip():
            user.nom_complet = data["nom_complet"].strip()

        if "email" in data and data["email"].strip():
            # Vérifier l'unicité de l'email
            existing_user = User.query.filter(User.email == data["email"].strip(), User.id != user.id).first()
            if existing_user:
                return jsonify({"error": "Email already exists!"}), 409
            user.email = data["email"].strip()

        if "telephone" in data and data["telephone"].strip():
            user.telephone = data["telephone"].strip()

        if "old_password" in data and "new_password" in data:
            if not user.check_password(data["old_password"]):
                return jsonify({"error": "Old password is incorrect!"}), 401
            user.set_password(data["new_password"])

        db.session.commit()

        return jsonify({"message": "Donator profile updated successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/get-profile-donator", methods=["GET"])
@jwt_required()
def get_profile_donator():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()
        if claims.get("role") != "donator":
            return jsonify({"error": "Access denied!"}), 403

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"error": "Donator profile not found"}), 404

        return jsonify({
            "nom_complet": user.nom_complet,
            "email": user.email,
            "telephone": user.telephone
        }), 200

    except Exception as e:
        print("Error fetching donator profile:", str(e))
        return jsonify({"error": str(e)}), 500

 # get by id the association infos
@app.route("/association/<int:id>", methods=["GET"])
@jwt_required()
def get_association_detail(id):
    try:
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Access denied!"}), 403

        association = Association.query.get(id)

        if not association:
            return jsonify({"error": "Association non trouvée."}), 404

      

        result = {
            "nom_complet": association.nom_complet,
            "email": association.email,
            "description_association": association.description_association,
            "telephone": association.telephone,
            "adresse": association.adresse,
            "type_association": association.type_association,
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# get profile of an association
@app.route("/get-profile-association", methods=["GET"])
@jwt_required()
def get_profile_association():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()

        if claims.get("role") != "association":
            return jsonify({"error": "Access denied!"}), 403

        # Fetch the user's association profile
        association = Association.query.filter_by(email=claims.get("email")).first()

        if not association:
            return jsonify({"error": "Association profile not found"}), 404

        # Return profile data
        return jsonify({
            "nom_complet": association.nom_complet,
            "email": association.email,
            "description_association": association.description_association,
            "telephone": association.telephone,
            "adresse": association.adresse,
            "type_association": association.type_association,
            "photo": association.photo,

        }), 200

    except Exception as e:
        print("Error fetching profile:", str(e))
        return jsonify({"error": str(e)}), 500

# ajouter don
@app.route("/create-don", methods=["POST"])
@jwt_required()
def create_don():
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied: only associations can create dons."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        association = Association.query.filter_by(email=user.email).first()
        if not association:
            return jsonify({"error": "Aucune association liée à ce compte."}), 404

        data = request.form
        file = request.files.get("photo_file")

        # Champs requis
        titre = data.get("titre")
        objectif_str = data.get("objectif")
        date_fin_collecte_str = data.get("date_fin_collecte")

        if not titre or not objectif_str or not date_fin_collecte_str:
            return jsonify({"error": "Titre, objectif et date_fin_collecte sont obligatoires."}), 400

        # Conversion float
        try:
            objectif = float(objectif_str)
        except Exception:
            return jsonify({"error": "L'objectif doit être un nombre"}), 400

        # Conversion date
        try:
            date_fin_collecte = datetime.strptime(date_fin_collecte_str, "%Y-%m-%d").date()
        except Exception:
            return jsonify({"error": "La date doit être au format AAAA-MM-JJ"}), 400

        # Image
        photo_path = None
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            photo_path = f"/static/uploads/{filename}"

        # Créer Don
        new_don = Don(
            titre=titre.strip(),
            description=data.get("description", "").strip(),
            objectif=objectif,
            montant_collecte=0.0,
            date_fin_collecte=date_fin_collecte,
            photo_don=photo_path,
            id_association=association.id_association,
            id_utilisateur=current_user_id,
            statut="en_attente",
        )

        db.session.add(new_don)
        db.session.commit()

        return jsonify({"message": "✅ Don créé avec succès !"}), 201

    except Exception as e:
        db.session.rollback()
        print("Erreur lors de la création du don:", str(e))
        return jsonify({"error": str(e)}), 500
    
# modifier don par l'association
@app.route("/update-don/<int:id_don>", methods=["PUT"])

@jwt_required()
def update_don(id_don):
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Accès refusé : seules les associations peuvent modifier un don."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        association = Association.query.filter_by(email=user.email).first()

        if not association:
            return jsonify({"error": "Association non trouvée."}), 404

        don = Don.query.filter_by(id_don=id_don, id_association=association.id_association).first()
        if not don:
            return jsonify({"error": "Don introuvable ou non autorisé."}), 404

        # Récupérer les données
        data = request.form
        file = request.files.get("photo_file")

        if "titre" in data:
            don.titre = data["titre"].strip()

        if "description" in data:
            don.description = data["description"].strip()

        if "objectif" in data:
            try:
                don.objectif = float(data["objectif"])
            except ValueError:
                return jsonify({"error": "L'objectif doit être un nombre"}), 400

        if "date_fin_collecte" in data:
            try:
                don.date_fin_collecte = datetime.strptime(data["date_fin_collecte"], "%Y-%m-%d").date()
            except ValueError:
                return jsonify({"error": "Date invalide. Format attendu : AAAA-MM-JJ"}), 400

        # 📷 Gestion du changement de photo
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            don.photo_don = f"/static/uploads/{filename}"

        db.session.commit()
        return jsonify({"message": "✅ Don mis à jour avec succès."}), 200

    except Exception as e:
        db.session.rollback()
        print("Erreur modification don :", str(e))
        return jsonify({"error": str(e)}), 500

# supprimer don par l'association
@app.route("/delete-don/<int:id_don>", methods=["DELETE"])
@jwt_required()
def delete_don(id_don):
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Accès refusé : seules les associations peuvent supprimer un don."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        association = Association.query.filter_by(email=user.email).first()

        don = Don.query.filter_by(id_don=id_don, id_association=association.id_association).first()
        if not don:
            return jsonify({"error": "Don introuvable ou accès non autorisé."}), 404

        db.session.delete(don)
        db.session.commit()
        return jsonify({"message": "🗑️ Don supprimé avec succès."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# valider don
@app.route("/don/<int:id_don>/valider", methods=["PUT"])
@jwt_required()
def valider_don(id_don):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    don = Don.query.get(id_don)
    if not don:
        return jsonify({"error": "Don introuvable"}), 404

    don.statut = "valide"
    id_assoc = don.id_association
    # ✅ Notification
    notif_assoc = Notification(
    contenu=f"Le don '{don.titre}' a été validé par l’administrateur.",
    id_association=id_assoc,
    is_read=False,
    id_don=don.id_don,
    date=datetime.utcnow()
)

    db.session.add(notif_assoc)
    # 🔔 Notifier tous les donateurs
    utilisateurs = User.query.filter_by(role='donator').all()
    for user in utilisateurs:
        notif = Notification(
            contenu=f"Nouveau don : {don.titre}",
            date=datetime.utcnow(),
            is_read=False,
            id_association=id_assoc,  
            id_user=user.id,
            id_don=don.id_don 
        )
        db.session.add(notif)

  

    db.session.commit()
    return jsonify({"message": "Don validé avec succès"}), 200


# Refuser don

@app.route("/don/<int:id_don>/refuser", methods=["PUT"])
@jwt_required()
def refuser_don(id_don):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    don = Don.query.get(id_don)
    if not don:
        return jsonify({"error": "Don introuvable"}), 404

    don.statut = "refuse"

    # ✅ Notification
    notif = Notification(
        contenu=f"Le don '{don.titre}' a été refusé par l’administrateur.",
        id_association=don.id_association,
        date=datetime.utcnow()
    )
    db.session.add(notif)

    # ✅ Email (optionnel)
    try:
        assoc = don.association
        if assoc and assoc.email:
            msg = Message(
                subject="Refus de votre don",
                sender=app.config.get("MAIL_DEFAULT_SENDER", "admin@donbyuib.tn"),
                recipients=[assoc.email],
                body=f"Bonjour {assoc.nom_complet},\n\nVotre don intitulé '{don.titre}' a été refusé par l'administrateur.\n\nMerci."
            )
            mail.send(msg)
    except Exception as e:
        print("Erreur lors de l’envoi de l’email :", e)

    db.session.commit()
    return jsonify({"message": "Don refusé avec succès"}), 200


# get dons pour l'admin 

@app.route("/admin/dons", methods=["GET"])
@jwt_required()
def get_all_dons_admin():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    dons = Don.query.all()
    result = []
    for don in dons:
        result.append({
            "id_don": don.id_don,
            "titre": don.titre,
            "description": don.description,
            "objectif": don.objectif,
            "montant_collecte": don.montant_collecte,
            "date_fin_collecte": don.date_fin_collecte.isoformat(),
            "photo_don": don.photo_don,
            "statut": don.statut,
            "association": don.association.nom_complet if don.association else "Inconnue"
        })

    return jsonify(result), 200

# valider publication

@app.route("/publication/<int:id_publication>/valider", methods=["PUT"])
@jwt_required()
def valider_publication(id_publication):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    publication = Publication.query.get(id_publication)
    if not publication:
        return jsonify({"error": "publication introuvable"}), 404

    publication.statut = "valide"
    id_assoc = publication.id_association
    # ✅ Notification
    notif_assoc = Notification(
        contenu=f"La publication '{publication.titre}' a été validée par l’administrateur.",
        date=datetime.utcnow(),
        is_read=False,
        id_association=id_assoc,
        id_publication=publication.id_publication
    )
    db.session.add(notif_assoc)
    # 🔔 Notifier tous les donateurs
    utilisateurs = User.query.filter_by(role='donator').all()
    for user in utilisateurs:
        notif = Notification(
            contenu=f"Nouvelle publication : {publication.titre}",
            date=datetime.utcnow(),
            is_read=False,
            id_association=id_assoc,  # ✅ On met ici la bonne valeur
            id_user=user.id,
            id_publication=publication.id_publication # (facultatif si tu veux rattacher la notif à la publication)
        )
        db.session.add(notif)
    

    db.session.commit()
    return jsonify({"message": "Publication validé avec succès"}), 200


@app.route("/publication/<int:id_publication>/refuser", methods=["PUT"])
@jwt_required()
def refuser_publication(id_publication):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    publication = Publication.query.get(id_publication)
    if not publication:
        return jsonify({"error": "Publication introuvable"}), 404

    publication.statut = "refuse"

    notif = Notification(
        contenu=f"La publication '{publication.titre}' a été refusée par l’administrateur.",
        id_publication=publication.id_publication,
        id_association=publication.id_association,  # ✅ ceci est nécessaire
        date=datetime.utcnow(),
        is_read=False  # si ce champ existe
    )
    db.session.add(notif)
    db.session.commit()

    return jsonify({"message": "Publication refusée avec succès"}), 200

# afficher les publications par l'admin 

@app.route("/admin/publications", methods=["GET"])
@jwt_required()
def get_all_publication_admin():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Accès refusé"}), 403

    publications = Publication.query.all()
    result = []
    for publication in publications:
        result.append({
            "id_publication": publication.id_publication,
            "titre": publication.titre,
            "contenu": publication.contenu,
            "date_publication": publication.date_publication.isoformat(),
            "statut": publication.statut
        })

    return jsonify(result), 200


# get dons by associations

@app.route("/dons", methods=["GET"])
@jwt_required()
def get_dons():
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied: only associations can view their dons."}), 403

        current_user_id = get_jwt_identity()

        dons = Don.query.filter_by(id_utilisateur=current_user_id).all()

        result = []
        for don in dons:
            result.append({
                "id_don": don.id_don,
                "titre": don.titre,
                "description": don.description,
                "montant_collecte": don.montant_collecte,
                "objectif":don.objectif,
                "date_fin_collecte": don.date_fin_collecte.isoformat(),
                "recu_don": don.recu_don,
                "photo_don": don.photo_don,
                "id_association": don.id_association
            })

        return jsonify(result), 200

    except Exception as e:
        print("Erreur lors de la récupération des dons:", str(e))
        return jsonify({"error": str(e)}), 500
#get all dons (to pagefront)
@app.route("/public-dons", methods=["GET"])
def get_all_dons_public():
    try:
        # ❗ Exclure les dons refusés et en attente
        dons = Don.query.filter(Don.statut == "valide").all()
        today = date.today()
        result = []
        

        for don in dons:
              pourcentage = round((don.montant_collecte / don.objectif) * 100) if don.objectif > 0 else 0
              result.append({
                "id_don": don.id_don,
                "titre": don.titre,
                "description": don.description,
                "montant_collecte": don.montant_collecte,
                "objectif": don.objectif,
                "date_fin_collecte": don.date_fin_collecte.isoformat(),
                "photo_don": don.photo_don,
                "nom_organisateur": don.association.nom_complet if don.association else "Inconnu",
                "id_association": don.id_association,
                "pourcentage": pourcentage,
                "is_expire": don.date_fin_collecte < today

            })

        return jsonify(result), 200

    except Exception as e:
        print("Erreur lors de la récupération des dons:", str(e))
        return jsonify({"error": str(e)}), 500
# voir les détails de l'association en public
@app.route("/public-association/<int:id>", methods=["GET"])
def get_public_association_detail(id):
    try:
        association = Association.query.get(id)

        if not association:
            return jsonify({"error": "Association non trouvée."}), 404

        result = {
            "nom_complet": association.nom_complet,
            "photo": association.photo,
            "description_association": association.description_association,
            "telephone": association.telephone,
            "adresse": association.adresse
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
#récupérer les détails des dons
@app.route("/don/<int:id>", methods=["GET"])
def get_don_by_id(id):
    don = Don.query.get(id)
    if not don:
        return jsonify({"error": "Don non trouvé"}), 404

    return jsonify({
        "id_don": don.id_don,
        "titre": don.titre,
        "description": don.description,
        "objectif": don.objectif,
        "montant_collecte": don.montant_collecte,
        "date_fin_collecte": don.date_fin_collecte.isoformat(),
        "photo_don": don.photo_don,
        "nom_organisateur": don.association.nom_complet if don.association else "Inconnu"
    }), 200



# participer aux dons

@app.route("/participate/<int:id_don>", methods=["POST"])
@jwt_required()
def participate(id_don):
    try:
        claims = get_jwt()
        if claims.get("role") != "donator":
            return jsonify({"error": "Seuls les donateurs peuvent participer."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "Utilisateur introuvable."}), 404

        don = Don.query.get(id_don)
        if not don:
            return jsonify({"error": "Don non trouvé."}), 404

        data = request.get_json()
        montant = data.get("montant")

        if not montant or float(montant) <= 0:
            return jsonify({"error": "Montant invalide."}), 400

        # Enregistrer la participation
        participation = Participation(
            montant=montant,
            id_don=id_don,
            id_user=current_user_id
        )

        db.session.add(participation)
        don.montant_collecte += float(montant)
        nb_unique_users = db.session.query(Participation.id_user).filter_by(id_don=id_don).distinct().count()
        don.nb_donateurs = nb_unique_users

# Vérifier si l’objectif est atteint
        if don.montant_collecte >= don.objectif:
            don.is_reussi = True
        db.session.commit()

        return jsonify({
            "message": "✅ Participation enregistrée avec succès.",
            "nom_complet": user.nom_complet,
            "email": user.email
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/don-participants", methods=["GET"])
def get_don_participants():
    try:
        results = db.session.query(
            Don.id_don,
            Don.titre,
            db.func.count(Participation.id_participation).label("nb_participants")
        ).outerjoin(Participation).group_by(Don.id_don).all()

        data = []
        for don_id, titre, nb in results:
            data.append({
                "id_don": don_id,
                "titre": titre,
                "nb_participants": nb
            })

        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)






# ajouter publication

from datetime import datetime

@app.route("/add-publications", methods=["POST"])
@jwt_required()
def create_publication():
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied: only associations can create publications."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        association = Association.query.filter_by(email=user.email).first()
        if not association:
            return jsonify({"error": "Aucune association liée à ce compte."}), 404

        data = request.get_json()
        titre = data.get("titre")
        contenu = data.get("contenu")

        if not titre or not contenu:
            return jsonify({"error": "Titre et contenu sont requis."}), 400

        new_pub = Publication(
            titre=titre.strip(),
            contenu=contenu.strip(),
            date_publication=datetime.utcnow().date(),
            id_association=association.id_association,
            statut="en_attente",
        )

        db.session.add(new_pub)
        db.session.commit()

        return jsonify({"message": "✅ Publication créée avec succès."}), 201

    except Exception as e:
        db.session.rollback()
        print("Erreur Publication:", str(e))
        return jsonify({"error": str(e)}), 500


# list publication

@app.route("/publications", methods=["GET"])
@jwt_required()
def get_publications():
    try:
        claims = get_jwt()
        role = claims.get("role")

        if role == "association":
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)

            association = Association.query.filter_by(email=user.email).first()
            if not association:
                return jsonify({"error": "Aucune association trouvée."}), 404

            publications = Publication.query.filter_by(id_association=association.id_association).all()

        elif role in ["donator", "admin"]:
            publications = Publication.query.all()
        else:
            return jsonify({"error": "Access denied!"}), 403

        result = []
        for pub in publications:
            commentaires = [
                {
                    "nom": User.query.get(com.id_user).nom_complet if com.id_user else "Utilisateur",
                    "contenu": com.contenu,
                    "sentiment": com.sentiment
                }
                for com in pub.commentaires 
            ]

            result.append({
                "id_publication": pub.id_publication,
                "titre": pub.titre,
                "contenu": pub.contenu,
                "date_publication": pub.date_publication.isoformat(),
                "nb_likes": pub.nb_likes,
                "nb_commentaires": pub.nb_commentaires,
                "nb_partages": pub.nb_partages,
                "nom_association": pub.association.nom_complet,
                "commentaires": commentaires  
            })

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# voir détails publication 

@app.route("/publication/<int:id>", methods=["GET"])
@jwt_required()
def get_publication_detail(id):
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied!"}), 403

        publication = Publication.query.get(id)

        if not publication:
            return jsonify({"error": "Publication non trouvée."}), 404

        commentaires_list = [
            {
                "id_commentaire": c.id_commentaire,
                "contenu": c.contenu,
                "date_commentaire": c.date_commentaire.isoformat(),
                "sentiment":c.sentiment
            } for c in publication.commentaires
        ]

        result = {
            "id_publication": publication.id_publication,
            "titre": publication.titre,
            "contenu": publication.contenu,
            "date_publication": publication.date_publication.isoformat(),
            "nb_likes": publication.nb_likes,
            "nb_commentaires": publication.nb_commentaires,
            "nb_partages": publication.nb_partages,
            "commentaires": commentaires_list
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# modifier publication

@app.route("/update-publication/<int:id>", methods=["PUT"])
@jwt_required()
def update_publication(id):
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied: only associations can update publications."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        association = Association.query.filter_by(email=user.email).first()

        if not association:
            return jsonify({"error": "Aucune association trouvée."}), 404

        publication = Publication.query.filter_by(id_publication=id, id_association=association.id_association).first()

        if not publication:
            return jsonify({"error": "Publication introuvable ou non autorisée."}), 404

        data = request.get_json()
        titre = data.get("titre")
        contenu = data.get("contenu")

        if titre:
            publication.titre = titre.strip()
        if contenu:
            publication.contenu = contenu.strip()

        db.session.commit()

        return jsonify({"message": "✅ Publication modifiée avec succès."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# delete publication
@app.route("/delete-publication/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_publication(id):
    try:
        claims = get_jwt()
        if claims.get("role") != "association":
            return jsonify({"error": "Access denied: only associations can delete publications."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        association = Association.query.filter_by(email=user.email).first()
        if not association:
            return jsonify({"error": "Aucune association trouvée."}), 404

        publication = Publication.query.filter_by(id_publication=id, id_association=association.id_association).first()

        if not publication:
            return jsonify({"error": "Publication introuvable ou non autorisée."}), 404

        db.session.delete(publication)
        db.session.commit()

        return jsonify({"message": "✅ Publication supprimée avec succès."}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500





# add commentaire 

@app.route("/add-comment/<int:publication_id>", methods=["POST"])
@jwt_required()
def add_comment(publication_id):
    try:
        claims = get_jwt()
        if claims.get("role") != "donator":
            return jsonify({"error": "Access denied: only donators can comment."}), 403

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        publication = Publication.query.get(publication_id)
        if not publication:
            return jsonify({"error": "Publication non trouvée."}), 404

        data = request.get_json()
        contenu_commentaire = data.get("contenu")

        if not contenu_commentaire or not contenu_commentaire.strip():
            return jsonify({"error": "Le contenu du commentaire est requis."}), 400

        # Analyse sentiment avec VADER
        scores = analyze_comment(contenu_commentaire)
        sentiment_label = get_sentiment_label(scores["compound"], contenu_commentaire)


        new_comment = Commentaire(
            contenu=contenu_commentaire.strip(),
            date_commentaire=datetime.utcnow().date(),
            sentiment=sentiment_label,
            id_publication=publication_id,
            id_user=current_user_id
        )

        db.session.add(new_comment)

        notif = Notification(
            contenu=f"Nouveau 💬 à {publication.titre} : {contenu_commentaire.strip()}",
            date=datetime.utcnow(),
            id_association=publication.id_association
        )
        db.session.add(notif)
        publication.nb_commentaires += 1
        db.session.commit()

        return jsonify({"message": "✅ Commentaire ajouté avec succès.", "sentiment": sentiment_label}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    
#get notification 

@app.route("/notifications", methods=["GET"])
@jwt_required()
def get_notifications():
    claims = get_jwt()
    if claims.get("role") != "association":
        return jsonify({"error": "Access denied!"}), 403

    user = User.query.get(get_jwt_identity())
    association = Association.query.filter_by(email=user.email).first()
    if not association:
        return jsonify({"error": "Association not found"}), 404

    notifs = Notification.query.filter_by(id_association=association.id_association).order_by(Notification.date.desc()).all()
    return jsonify([
        {
            "id": n.id,
            "contenu": n.contenu,
            "date": n.date.isoformat(),
            "is_read": n.is_read
        }
        for n in notifs
    ])

#notification donateur

@app.route("/notifications-donator", methods=["GET"])
@jwt_required()
def get_notifications_donator():
    claims = get_jwt()
    if claims.get("role") != "donator":
        return jsonify({"error": "Access denied!"}), 403

    current_user_id = get_jwt_identity()

    notifs = Notification.query.filter_by(id_user=current_user_id).order_by(Notification.date.desc()).all()
    return jsonify([
        {
            "id": n.id,
            "contenu": n.contenu,
            "date": n.date.isoformat(),
            "is_read": n.is_read
        }
        for n in notifs
    ])





@app.route("/pay-flouci", methods=["POST"])
@jwt_required()
def pay_flouci():
    try:
        data = request.get_json()
        amount = data.get("amount")

        if not amount:
            return jsonify({"error": "Montant requis."}), 400

        amount_millimes = int(float(amount) * 1000)

        payload = {
            "app_token": "b4af24ad-5d18-4eda-9299-c86beb4dd9e4",      
            "app_secret": "4a249c02-181c-4bd5-b350-542a99a4ffc7",    
            "amount": str(amount_millimes),
            "accept_card": "true",
            "session_timeout_secs": 1200,
            "success_link": "http://localhost:4200/#/success",  
            "fail_link": "http://localhost:4200/#/fail",
            "developer_tracking_id": "donbyuib-20240423"
        }

        headers = {
            "Content-Type": "application/json"
        }

        url = "https://developers.flouci.com/api/generate_payment"

        # 1️⃣ Appel à Flouci
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code in [200, 201]:
            flouci_result = response.json()
            payment_id = flouci_result.get("result", {}).get("payment_id")
            payment_link = flouci_result.get("result", {}).get("link")

            # 2️⃣ On ajoute le payment_id comme paramètre à la fin du lien
            if payment_id and payment_link:
                # Ajoute payment_id à la query string du lien de paiement Flouci (option recommandé)
                # -> Surtout à utiliser dans success_link côté Flouci dashboard, ou passer payment_id à Angular !
                redirect_link = f"{payment_link}?payment_id={payment_id}"
                return jsonify({"result": {"link": redirect_link, "payment_id": payment_id}}), 200
            else:
                return jsonify({"error": "Payment ID ou lien non reçu de Flouci"}), 500
        else:
            return jsonify({"error": response.text}), response.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
# pour vérifier le paiement qui a été bien effectué

@app.route("/verify-flouci-payment/<payment_id>", methods=["GET"])
def verify_flouci_payment(payment_id):
    try:
        url = f"https://developers.flouci.com/api/verify_payment/{payment_id}"

        headers = {
            'Content-Type': 'application/json',
            'apppublic': "b4af24ad-5d18-4eda-9299-c86beb4dd9e4",   # Mets ici ton app_token (public)
            'appsecret': "4a249c02-181c-4bd5-b350-542a99a4ffc7"   # Mets ici ton app_secret (privé)
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Exemple : {'success': True, 'result': {'status': 'SUCCESS', ...}}
            return jsonify(data), 200
        else:
            return jsonify({"error": response.text}), response.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500


           


@app.route("/like-publication/<int:publication_id>", methods=["POST"])
@jwt_required()
def like_publication(publication_id):
    try:
        claims = get_jwt()
        if claims.get("role") not in ["donator", "admin","association"]:
            return jsonify({"error": "Seuls les utilisateurs peuvent liker."}), 403

        publication = Publication.query.get(publication_id)
        if not publication:
            return jsonify({"error": "Publication non trouvée."}), 404

        publication.nb_likes += 1
        db.session.commit()

        return jsonify({"message": "👍 Publication likée", "nb_likes": publication.nb_likes}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# analyser sentiment d'un donateur

from deep_translator import GoogleTranslator
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

def analyze_comment(comment_text):
    # Traduire le texte en anglais
    translated = GoogleTranslator(source='auto', target='en').translate(comment_text)
    analyzer = SentimentIntensityAnalyzer()
    scores = analyzer.polarity_scores(translated)
    return scores


def get_sentiment_label(compound_score, comment):
    comment = comment.lower()
    mots_positifs = ['bravo', 'merci', 'parfait', 'génial', 'félicitations', 'don', 'aider','bonne','bon courage','meilleur']

    if any(mot in comment for mot in mots_positifs):
        return "positif"
    elif compound_score >= 0.05:
        return "positif"
    elif compound_score <= -0.05:
        return "négatif"
    else:
        return "neutre"


# get paiements
@app.route("/mes-paiements", methods=["GET"])
@jwt_required()
def get_paiements_donator():
    try:
        claims = get_jwt()
        if claims.get("role") != "donator":
            return jsonify({"error": "Accès refusé"}), 403

        current_user_id = get_jwt_identity()

        participations = Participation.query.filter_by(id_user=current_user_id).join(Don).all()
        result = []
        for p in participations:
            result.append({
                "id_participation": p.id_participation,
                "titre_don": p.don.titre,
                "montant": p.montant,
                "date": p.date_participation.isoformat(),
                "photo_don": p.don.photo_don
            })

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
#recu de paiement
from flask import make_response, send_file
from xhtml2pdf import pisa
from io import BytesIO
import qrcode
import base64
from flask_jwt_extended import jwt_required, get_jwt_identity
import os

@app.route('/recu-pdf/<int:id_participation>', methods=['GET'])
@jwt_required()
def generate_recu_pdf(id_participation):
    participation = Participation.query.get(id_participation)
    if not participation:
        return jsonify({"error": "Participation introuvable"}), 404

    don = participation.don
    user = participation.user

    """ # 🧠 Génération QR Code dynamique
    association_id = don.id_association
    qr_data = f"http://localhost:4200/#/detail-association/{association_id}"

    qr_img = qrcode.make(qr_data)
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_base64 = base64.b64encode(qr_buffer.getvalue()).decode("utf-8") """

    # 📷 Logo UIB (sous static/uploads/uiblogo.png)
    logo_path = os.path.join(app.root_path, 'static', 'uploads', 'uiblogo.png')
    with open(logo_path, "rb") as image_file:
        logo_base64 = base64.b64encode(image_file.read()).decode("utf-8")

    # 📄 HTML du reçu
    html = f"""
    <html>
      <head>
        <style>
          body {{ font-family: Arial, sans-serif; padding: 20px; }}
          .header {{ text-align: center; }}
          .logo {{ width: 100px; }}
          .content {{ margin-top: 30px; }}
          .section {{ margin-bottom: 10px; }}
          
          .footer {{ text-align: center; margin-top: 50px; font-size: 12px; color: #555; }}
        </style>
      </head>
      <body>
        <div class="header">
          <img class="logo" src="data:image/png;base64,{logo_base64}" />
          <h2 style="color: #e53935;">Reçu de Paiement - DonByUIB</h2>
        </div>

        <div class="content">
          <div class="section"><strong>Nom du Donateur :</strong> {user.nom_complet}</div>
          <div class="section"><strong>Email :</strong> {user.email}</div>
          <div class="section"><strong>Campagne :</strong> {don.titre}</div>
          <div class="section"><strong>Montant :</strong> {participation.montant} TND</div>
          <div class="section"><strong>Date :</strong> {participation.date_participation.strftime('%d/%m/%Y')}</div>
        </div>

   


        <div class="footer">
          Ce reçu est généré automatiquement par DonByUIB.<br>
          Merci pour votre soutien et votre générosité.
        </div>
      </body>
    </html>
    """

    # Génération PDF
    buffer = BytesIO()
    pisa_status = pisa.CreatePDF(BytesIO(html.encode('utf-8')), dest=buffer)
    if pisa_status.err:
        return jsonify({"error": "Erreur lors de la génération du PDF"}), 500

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=recu_{id_participation}.pdf'
    return response

# historique du donateur 

@app.route("/historique-donateur", methods=["GET"])
@jwt_required()
def get_historique_donateur():
    try:
        claims = get_jwt()
        if claims.get("role") != "donator":
            return jsonify({"error": "Accès refusé"}), 403

        current_user_id = get_jwt_identity()

        # Récupérer participations
        participations = Participation.query.filter_by(id_user=current_user_id).join(Don).all()
        dons = [{
            "type": "don",
            "titre_don": p.don.titre,
            "montant": p.montant,
            "date": p.date_participation.isoformat(),
            "photo_don": p.don.photo_don
        } for p in participations]

        # Récupérer commentaires
        commentaires = Commentaire.query.filter_by(id_user=current_user_id).join(Publication).all()
        comments = [{
            "type": "commentaire",
            "publication": c.publication.titre,
            "contenu": c.contenu,
            "date": c.date_commentaire.isoformat(),
            "sentiment": c.sentiment
        } for c in commentaires]

        historique = sorted(dons + comments, key=lambda x: x['date'], reverse=True)

        return jsonify(historique), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

""" 
# Moteur de recommendation pour extraire les dons selon préférences du donateur
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

@app.route("/recommandations", methods=["GET"])
@jwt_required()
def recommander_dons():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user.role != "donator":
        return jsonify({"error": "Seuls les donateurs peuvent recevoir des recommandations"}), 403

    participations = Participation.query.filter_by(id_user=user_id).all()
    if not participations:
        return jsonify({"message": "Aucune participation, recommander les dons populaires"}), 200

    # Récupérer les dons auxquels il a participé
    dons_ids = [p.id_don for p in participations]
    user_dons = Don.query.filter(Don.id_don.in_(dons_ids)).all()

    # Construire le corpus (titre + description)
    user_texts = [d.titre + " " + (d.description or "") for d in user_dons]
    user_text = " ".join(user_texts)

    # Tous les autres dons valides
    all_dons = Don.query.filter(Don.statut == "valide").all()
    all_texts = [don.titre + " " + (don.description or "") for don in all_dons]

    # TF-IDF + similarité cosinus
    tfidf = TfidfVectorizer(stop_words='english')
    tfidf_matrix = tfidf.fit_transform([user_text] + all_texts)
    cosine_similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:]).flatten()

    # Associer similarités avec les dons
    dons_scores = [
        {"don": don, "score": score}
        for don, score in zip(all_dons, cosine_similarities)
        if don.id_don not in dons_ids  # Ne pas recommander les dons déjà soutenus
    ]
    dons_scores.sort(key=lambda x: x["score"], reverse=True)

    recommandations = [
        {
            "id_don": d["don"].id_don,
            "titre": d["don"].titre,
            "description": d["don"].description,
            "photo_don": d["don"].photo_don,
            "montant_collecte": d["don"].montant_collecte,
            "objectif": d["don"].objectif,
            "score": round(d["score"], 2)
        }
        for d in dons_scores[:5]  # Recommander les 5 meilleurs
    ]

    return jsonify(recommandations), 200 """




# ------------------- DATABASE MIGRATION -------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)