import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
import os

app = Flask(__name__)
app.config ["SECRET_KEY"] = os.environ.get('SECRET_KEY', 'dev-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {"check_same_thread": False}
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, async_mode="eventlet", manage_session=False)


#----Modelas----#
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password :str):
        self.password = generate_password_hash(password)
    
    def check_password(self, password :str) -> bool:
        return check_password_hash(self.password, password)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
    # Create the database tables
with app.app_context():
    db.create_all()
    
#routes
@app.route('/')
@login_required
def index():
    return redirect(url_for("chat"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please fill out both fields.')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful.')
            return redirect(url_for('chat'))
        flash('Invalid username or password.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', username=current_user.username)

#----SocketIO----#
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    join_room('global')
    emit("system",{"msg": f"{current_user.username} has joined the chat."}, to='global')
    print(f"{current_user.username} connected.")
@socketio.on("SendMsg")
def handle_send_message(data):
    if not current_user.is_authenticated:
        return False
    text = (data or {}).get("msg", "").strip()
    if not text:
        return
    print("📩 Server received:", text)   # 👈 add this
    emit("receive_message",
         {"user": current_user.username, "msg": text},
         to="global")
if __name__ == "__main__":
    import eventlet.wsgi
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
