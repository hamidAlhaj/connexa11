# connexa_app.py
"""Single-file Connexa starter:
- Flask REST API (register/login, create conversation, list convs, messages)
- Flask-SocketIO realtime (connect with JWT, join room, send_message)
- Uses SQLAlchemy (works with MySQL if DATABASE_URI is set, defaults to sqlite dev.db)
"""
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
)
from flask_socketio import SocketIO, join_room, emit
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "jwt-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///dev.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    is_group = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def user_to_dict(u):
    return {"id": u.id, "username": u.username, "email": u.email}

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    if not username or not email or not password:
        return jsonify({"msg": "username, email, password required"}), 400
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"msg": "user already exists"}), 400
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, email=email, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=str(user.id))
    #token = create_access_token(identity=user.id)
    return jsonify({"access_token": token, "user": user_to_dict(user)}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"msg": "email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"msg": "invalid credentials"}), 401
    token = create_access_token(identity=str(user.id))
   # token = create_access_token(identity=user.id)
    return jsonify({"access_token": token, "user": user_to_dict(user)})

@app.route("/api/conversations", methods=["GET", "POST"])
@jwt_required()
def conversations():
    user_id = get_jwt_identity()
    if request.method == "GET":
        parts = Participant.query.filter_by(user_id=user_id).all()
        convs = []
        for p in parts:
            c = Conversation.query.get(p.conversation_id)
            convs.append({"id": c.id, "title": c.title, "is_group": c.is_group})
        return jsonify(convs)

    data = request.get_json() or {}
    title = data.get("title")
    is_group = bool(data.get("is_group", False))
    participant_ids = data.get("participant_ids", [])
    if user_id not in participant_ids:
        participant_ids.append(user_id)

    conv = Conversation(title=title, is_group=is_group)
    db.session.add(conv)
    db.session.flush()
    for uid in set(participant_ids):
        p = Participant(conversation_id=conv.id, user_id=uid)
        db.session.add(p)
    db.session.commit()
    return jsonify({"id": conv.id, "title": conv.title}), 201

@app.route("/api/conversations/<int:conv_id>/messages", methods=["GET", "POST"])
@jwt_required()
def conv_messages(conv_id):
    user_id = get_jwt_identity()
    if not Participant.query.filter_by(conversation_id=conv_id, user_id=user_id).first():
        return jsonify({"msg": "not allowed"}), 403
    if request.method == "GET":
        msgs = Message.query.filter_by(conversation_id=conv_id).order_by(Message.created_at.asc()).limit(200).all()
        out = []
        for m in msgs:
            out.append({"id": m.id, "sender_id": m.sender_id, "body": m.body, "created_at": m.created_at.isoformat()})
        return jsonify(out)
    data = request.get_json() or {}
    body = data.get("body")
    if not body:
        return jsonify({"msg": "body required"}), 400
    msg = Message(conversation_id=conv_id, sender_id=user_id, body=body)
    db.session.add(msg)
    db.session.commit()
    out = {"id": msg.id, "conversation_id": conv_id, "sender_id": user_id, "body": body, "created_at": msg.created_at.isoformat()}
    try:
        socketio.emit("new_message", out, room=str(conv_id))
    except Exception:
        pass
    return jsonify(out), 201

@socketio.on("connect")
def socket_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get("token")
    if not token:
        print("Socket connect: no token provided -> reject")
        return False
    try:
        data = decode_token(token)
        user_id = data["sub"]
        print(f"Socket connected: user {user_id}")
    except Exception as e:
        print("Socket auth failed:", e)
        return False

@socketio.on("join_room")
def on_join(data):
    conv_id = data.get("conversation_id")
    if conv_id is None:
        emit("error", {"msg": "conversation_id required"})
        return
    room = str(conv_id)
    join_room(room)
    emit("joined_room", {"room": room})

@socketio.on("send_message")
def on_send(data):
    conv_id = data.get("conversation_id")
    sender_id = data.get("sender_id")
    body = data.get("body")
    if not conv_id or not sender_id or not body:
        emit("error", {"msg": "conversation_id, sender_id, body required"})
        return
    msg = Message(conversation_id=conv_id, sender_id=sender_id, body=body)
    db.session.add(msg)
    db.session.commit()
    out = {"id": msg.id, "conversation_id": conv_id, "sender_id": sender_id, "body": body, "created_at": msg.created_at.isoformat()}
    emit("new_message", out, room=str(conv_id))

# Ensure tables are created when the app starts (compatible with Flask 3+)
def ensure_tables_on_startup():
    with app.app_context():
        db.create_all()

# call once at startup
ensure_tables_on_startup()

if __name__ == "__main__":
    print("Starting Connexa server...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
