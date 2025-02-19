from flask import Flask, render_template, request, redirect, url_for, make_response
from markupsafe import Markup
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

from flask import g
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import eventlet
import eventlet.wsgi
from flask import send_from_directory



app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = '88558992340'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB limit


db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=120, ping_interval=30)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    photo = db.Column(db.String(200), nullable=True)  # Store photo filename or path
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)

    #ye friend request k liye hai
    def is_friend(self, user):
        # Check if there's an accepted friendship
        return FriendRequest.query.filter(
            ((FriendRequest.sender_id == self.id) & (FriendRequest.receiver_id == user.id) & (FriendRequest.status == "accepted")) |
            ((FriendRequest.sender_id == user.id) & (FriendRequest.receiver_id == self.id) & (FriendRequest.status == "accepted"))
        ).count() > 0

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(200), nullable=True)  # New field for post images
    comments = db.relationship('Comment', backref='post', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default="pending")  # Can be "pending", "accepted", "rejected"
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ✅ Make sure this is present
    content = db.Column(db.Text, nullable=True)  # Message text
    attachment = db.Column(db.String(200), nullable=True)  # Filename
    attachment_type = db.Column(db.String(50), nullable=True)  # 'photo', 'video', 'audio'
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')





@app.route('/')
def home():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        username = decoded_token['user']
        user = User.query.filter_by(username=username).first()
        posts = Post.query.filter_by(user_id=user.id).all()
        users = User.query.all()  # sab users data fetch karta ye
        return render_template('home.html', user=user, posts=posts, users=users)
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))

@app.context_processor
def inject_user():
    return {'current_user': g.current_user}

@app.route('/profile/<username>')
def profile(username):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.filter_by(username=decoded_token['user']).first()
        user = User.query.filter_by(username=username).first()

        if not user:
            return "User not found", 404

        posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).all()

        # 🔍 Debugging Logs
        print(f"Profile of: {user.username}, User ID: {user.id}")
        print(f"Total Posts Found: {len(posts)}")
        for post in posts:
            print(f"Post ID: {post.id}, Content: {post.content}")

        can_add_friend = not current_user.is_friend(user)

        return render_template('profile.html', user=user, current_user=current_user, posts=posts, can_add_friend=can_add_friend)

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            print(f"Token: {token}")  # ye token Print karta hai
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('token', token)
            return resp

        return "Invalid credentials"

    return render_template('login.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Existing registration fields
        email = request.form['email']
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        date_of_birth = request.form['date_of_birth']
        password = request.form['password']
        
        # Photo upload handling
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo and photo.filename != '':
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config[' UPLOAD_FOLDER'], filename))
            else:
                filename = None  # No file selected
        else:
            filename = None


        # Save user with photo
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=datetime.datetime.strptime(date_of_birth, '%Y-%m-%d'),
            password=hashed_password,
            photo=filename  # Store photo filename
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred: {e}")
            return "Registration failed"

    return render_template('register.html')


@app.route('/send_request/<int:user_id>', methods=['POST'])
def send_request(user_id):
    # Check if the user is authenticated
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        # Decode the token and find the current (sender) user
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        sender = User.query.filter_by(username=decoded_token['user']).first()
        receiver = User.query.get(user_id)

        # Check if sender or receiver exists
        if not sender or not receiver:
            return "User not found", 404

        # Check if a request already exists or they are already friends
        existing_request = FriendRequest.query.filter_by(sender_id=sender.id, receiver_id=receiver.id).first()
        if existing_request:
            return "Friend request already sent or pending"

        # Create a new friend request with status "pending"
        friend_request = FriendRequest(sender_id=sender.id, receiver_id=receiver.id, status="pending")
        db.session.add(friend_request)
        db.session.commit()

        # Redirect back to the receiver's profile
        return redirect(url_for('profile', username=receiver.username))
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))




@app.route('/accept_request/<int:request_id>', methods=['POST'])
def accept_request(request_id):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        # Decode the token to get the current (receiver) user
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.filter_by(username=decoded_token['user']).first()
        friend_request = FriendRequest.query.get(request_id)

        # Ensure the request exists and the current user is the receiver
        if friend_request and friend_request.receiver_id == user.id:
            friend_request.status = "accepted"
            db.session.commit()
            return redirect(url_for('profile', username=user.username))
        return "Request not found or unauthorized"
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))


@app.route('/unfriend/<int:user_id>', methods=['POST'])
def unfriend(user_id):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.filter_by(username=decoded_token['user']).first()
        friend = User.query.get(user_id)

        if not friend:
            return "User not found", 404

        # Find the friend request where either current_user is sender or receiver with the given user
        friendship = FriendRequest.query.filter(
            ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == friend.id) & (FriendRequest.status == "accepted")) |
            ((FriendRequest.sender_id == friend.id) & (FriendRequest.receiver_id == current_user.id) & (FriendRequest.status == "accepted"))
        ).first()

        if friendship:
            # friendship delete krne ka function
            db.session.delete(friendship)
            db.session.commit()
            return redirect(url_for('profile', username=friend.username))
        else:
            return "Friendship not found", 404
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))



@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        username = decoded_token['user']
        user = User.query.filter_by(username=username).first()

        # Handle the image upload
        image = request.files['image']
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        # Create a new post with content and image
        new_post = Post(content=content, author=user, image=filename)

        try:
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred: {e}")
            return "Failed to create post"

    return render_template('create_post.html')


@app.route('/upload_photo', methods=['GET', 'POST'])
def upload_photo():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        username = decoded_token['user']
        user = User.query.filter_by(username=username).first()
        
        if request.method == 'POST' and 'photo' in request.files:
            photo = request.files['photo']
            if photo:
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.photo = filename  # Update photo filename in database

                db.session.commit()
                return redirect(url_for('profile', username=user.username))

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))

    return render_template('upload_photo.html')


@app.before_request
def load_current_user():
    token = request.cookies.get('token')
    if token:
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user = User.query.filter_by(username=decoded_token['user']).first()
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            g.current_user = None
    else:
        g.current_user = None


@app.route('/search', methods=['GET', 'POST'])
def search():
    query = None
    results = []
    if request.method == 'POST':
        query = request.form.get('search_query', '').strip()
        if query:
            results = User.query.filter(
                (User.username.ilike(f"%{query}%")) |
                (User.first_name.ilike(f"%{query}%")) |
                (User.last_name.ilike(f"%{query}%"))
            ).all()
    return render_template('search.html', query=query, results=results)



@socketio.on('connect')
def handle_connect():
    print("User connected")


@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if not username:
        print("Join event received without a username.")
        return

    room = f"user_{username}"
    join_room(room)
    print(f"{username} joined room {room}")


@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

import base64

@socketio.on('message')
def handle_message(data):
    sender_username = data.get('sender')
    receiver_username = data.get('receiver')
    content = data.get('content', None)
    attachment_name = data.get('attachment', None)
    attachment_type = data.get('attachmentType', None)
    file_data = data.get('fileData', None)

    sender = User.query.filter_by(username=sender_username).first()
    receiver = User.query.filter_by(username=receiver_username).first()

    if sender is None or receiver is None:
        emit('error', {'message': 'Invalid sender or receiver'})
        return

    attachment_path = None
    if file_data and attachment_name:
        try:
            file_bytes = base64.b64decode(file_data)
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment_name)

            with open(attachment_path, "wb") as f:
                f.write(file_bytes)
            print(f"✅ File saved at {attachment_path}")

        except Exception as e:
            print(f"⚠️ File saving error: {e}")
            return

    message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content=content,
        attachment=attachment_name if attachment_path else None,
        attachment_type=attachment_type if attachment_path else None
    )
    db.session.add(message)
    db.session.commit()

    message_payload = {
        'id': message.id,
        'sender': sender.username,
        'receiver': receiver.username,
        'content': content,
        'attachment': attachment_name if attachment_path else None,
        'attachment_type': attachment_type if attachment_path else None,
        'timestamp': message.timestamp.isoformat()
    }

    sender_room = f"user_{sender.username}"
    receiver_room = f"user_{receiver.username}"

    emit('new_message', message_payload, to=sender_room)
    emit('new_message', message_payload, to=receiver_room)


@app.route('/message/<username>')
def message_page(username):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        current_user = User.query.filter_by(username=decoded_token['user']).first()
        receiver = User.query.filter_by(username=username).first()

        if not receiver:
            return "User not found", 404

        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver.id)) |
            ((Message.sender_id == receiver.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.asc()).all()

        return render_template('message.html', sender=current_user, receiver=receiver, messages=messages)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return redirect(url_for('login'))

# from here it is for video chat and audio chat


@app.route("/video_chat")
def video_chat():
    return render_template("message.html")

@socketio.on("offer")
def handle_offer(data):
    emit("offer", data, broadcast=True)

@socketio.on("answer")
def handle_answer(data):
    emit("answer", data, broadcast=True)

@socketio.on("ice-candidate")
def handle_ice_candidate(data):
    emit("ice-candidate", data, broadcast=True)

@socketio.on("end-call")
def handle_end_call():
    emit("end-call", broadcast=True)

@socketio.on("call-initiated")
def handle_call_initiation(data):
    receiver = data["receiver"]
    emit("incoming-call", data, room=f"user_{receiver}")

@socketio.on("call-rejected")
def handle_call_rejection(data):
    caller = data["caller"]
    emit("call-rejected", {"message": "Call declined"}, room=f"user_{caller}")





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host="0.0.0.0", port=5000)