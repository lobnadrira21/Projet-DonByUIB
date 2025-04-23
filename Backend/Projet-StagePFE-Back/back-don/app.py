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


app = Flask(__name__)

CORS(app, resources={r"/*": {
    "origins": ["http://localhost:4200"],
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
    description = db.Column(db.String(255), nullable=True)
    objectif = db.Column(db.Float, nullable=False)
    montant_collecte = db.Column(db.Float, default=0.0)
    date_fin_collecte = db.Column(db.Date, nullable=False)
    recu_don = db.Column(db.String(255), nullable=True)
    photo_don = db.Column(db.String(255), nullable=True)
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

    association = db.relationship("Association", backref=db.backref("notifications", lazy=True, cascade="all, delete-orphan"))


# ---------- Methods ---------
@app.before_request
def handle_options_request():
    if request.method == "OPTIONS":  # Handle preflight requests
        response = jsonify({"message": "CORS preflight request successful"})
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response, 200






@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    nom_complet = data.get("nom_complet")
    telephone = data.get("telephone")
    role = data.get("role", "donator")  # Default role is 'donator' if not provided

    if not email or not password or not nom_complet or not telephone:
        return jsonify({"error": "All fields are required"}), 400

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



@app.route("/modify-profile-association", methods=["PUT"])
@jwt_required()
def modify_association():
    try:
        current_user_id = get_jwt_identity()
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

        # ✅ Sauvegarde du fichier photo
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            association.photo = f"/static/uploads/{filename}"

        db.session.commit()

        return jsonify({"message": "Association profile updated successfully!"}), 200

    except Exception as e:
        db.session.rollback()
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500



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

        # 🔍 Trouver l'association liée à cet utilisateur
        association = Association.query.filter_by(email=user.email).first()
        if not association:
            return jsonify({"error": "Aucune association liée à ce compte."}), 404

        data = request.form
        file = request.files.get("photo_file")

        # ✅ Champs requis
        titre = data.get("titre")
        objectif = data.get("objectif")
        date_fin_collecte = data.get("date_fin_collecte")

        if not titre or not objectif or not date_fin_collecte:
            return jsonify({"error": "Titre, objectif et date_fin_collecte sont obligatoires."}), 400


        # ✅ Sauvegarder l’image si elle est présente
        photo_path = None
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            photo_path = f"/static/uploads/{filename}"

        # ✅ Créer l’objet Don
        new_don = Don(
        titre=titre.strip(),
        description=data.get("description", "").strip(),
        objectif=float(objectif),  # ✅ nouveau champ
        montant_collecte=0.0,      # ✅ commence à 0
        date_fin_collecte=date_fin_collecte,
        recu_don=None,
        photo_don=photo_path,
        id_association=association.id_association,
        id_utilisateur=current_user_id
)


        db.session.add(new_don)
        db.session.commit()

        return jsonify({"message": "✅ Don créé avec succès !"}), 201

    except Exception as e:
        db.session.rollback()
        print("Erreur lors de la création du don:", str(e))
        return jsonify({"error": str(e)}), 500



# get dons

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
        dons = Don.query.all()

        result = []
        for don in dons:
            result.append({
                "id_don": don.id_don,
                "titre": don.titre,
                "description": don.description,
                "montant_collecte": don.montant_collecte,
                "objectif": don.objectif,
                "date_fin_collecte": don.date_fin_collecte.isoformat(),
                "photo_don": don.photo_don,
                "nom_organisateur": don.association.nom_complet if don.association else "Inconnu"

            })

        return jsonify(result), 200

    except Exception as e:
        print("Erreur lors de la récupération des dons:", str(e))
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
            id_association=association.id_association
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
                    "contenu": com.contenu
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
                "date_commentaire": c.date_commentaire.isoformat()
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

        if not user:
            return jsonify({"error": "Utilisateur non trouvé."}), 404

        publication = Publication.query.get(publication_id)
        if not publication:
            return jsonify({"error": "Publication non trouvée."}), 404

        data = request.get_json()
        contenu_commentaire = data.get("contenu")

        if not contenu_commentaire or not contenu_commentaire.strip():
            return jsonify({"error": "Le contenu du commentaire est requis."}), 400

        new_comment = Commentaire(
            contenu=contenu_commentaire.strip(),
            date_commentaire=datetime.utcnow().date(),
            id_publication=publication_id,
            id_user=current_user_id
        )

        db.session.add(new_comment)

        notif = Notification(
            contenu=f"Nouveau 💬 à {publication.titre} : {contenu_commentaire.strip()}",
            date=datetime.utcnow(),
            id_association=publication.id_association
        )
        print("🟢 Notification à enregistrer :", notif.contenu)

        db.session.add(notif)
        publication.nb_commentaires += 1
        db.session.commit()

        return jsonify({"message": "✅ Commentaire ajouté avec succès."}), 201

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


# ------------------- DATABASE MIGRATION -------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)