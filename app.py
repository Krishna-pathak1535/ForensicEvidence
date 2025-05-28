import os
import json
import hashlib
import datetime
from io import BytesIO
from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from encrypt import encrypt_file_bytes, decrypt_file_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blockchain.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

DIFFICULTY = 3  # number of leading zeros required in hash

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class BlockModel(db.Model):
    index = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    evidence_hash = db.Column(db.String(64), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)
    filename = db.Column(db.String(256), nullable=True)

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "block_hash": self.block_hash,
            "filename": self.filename
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('login'))

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(BlockModel, db.session))

def create_tables():
    with app.app_context():
        db.create_all()
        # Create genesis block if none exists
        if BlockModel.query.count() == 0:
            timestamp = str(datetime.datetime.utcnow())
            genesis_data = {
                "index": 0,
                "timestamp": timestamp,
                "evidence_hash": "Genesis",
                "previous_hash": "0",
                "nonce": 0,
                "filename": None
            }
            genesis_hash = hashlib.sha256(json.dumps(genesis_data, sort_keys=True).encode()).hexdigest()
            genesis_block = BlockModel(
                index=0,
                timestamp=timestamp,
                evidence_hash="Genesis",
                previous_hash="0",
                nonce=0,
                block_hash=genesis_hash,
                filename=None
            )
            db.session.add(genesis_block)
            db.session.commit()
            # Create admin user if none exists
            if not User.query.filter_by(is_admin=True).first():
                admin_user = User(
                    username='admin',
                    password=bcrypt.generate_password_hash('admin').decode('utf-8'),
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()

# Initialize the database when the app starts
create_tables()


def compute_hash(index, timestamp, evidence_hash, previous_hash, nonce, filename):
    block_data = {
        "index": index,
        "timestamp": timestamp,
        "evidence_hash": evidence_hash,
        "previous_hash": previous_hash,
        "nonce": nonce,
        "filename": filename
    }
    block_string = json.dumps(block_data, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()

def proof_of_work(index, timestamp, evidence_hash, previous_hash, filename):
    nonce = 0
    computed_hash = compute_hash(index, timestamp, evidence_hash, previous_hash, nonce, filename)
    while not computed_hash.startswith('0' * DIFFICULTY):
        nonce += 1
        computed_hash = compute_hash(index, timestamp, evidence_hash, previous_hash, nonce, filename)
    return nonce, computed_hash

@app.route('/')
def index():
    return redirect(url_for('upload_file'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file uploaded.', 'danger')
            return redirect(request.url)

        file_data = file.read()
        encrypted_data, evidence_hash = encrypt_file_bytes(file_data)

        filename = file.filename + ".enc"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        last_block = BlockModel.query.order_by(BlockModel.index.desc()).first()
        index = last_block.index + 1
        timestamp = str(datetime.datetime.utcnow())
        previous_hash = last_block.block_hash
        nonce, block_hash = proof_of_work(index, timestamp, evidence_hash, previous_hash, filename)

        new_block = BlockModel(
            index=index,
            timestamp=timestamp,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            nonce=nonce,
            block_hash=block_hash,
            filename=filename
        )
        db.session.add(new_block)
        db.session.commit()

        flash('File uploaded, encrypted, and stored on blockchain.', 'success')
        return redirect(url_for('upload_file'))

    # Also pass last few blocks for display on upload page
    blocks = BlockModel.query.order_by(BlockModel.index.desc()).limit(5).all()
    return render_template('upload.html', blocks=blocks)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('File not found.', 'danger')
        return redirect(url_for('upload_file'))

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file_bytes(encrypted_data)
    return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=filename.replace(".enc", ""))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('upload_file'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('upload_file'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# New route to view full blockchain
@app.route('/chain')
@login_required
def view_chain():
    blocks = BlockModel.query.order_by(BlockModel.index.asc()).all()
    return render_template('chain.html', chain=blocks)

# New route to verify blockchain integrity
@app.route('/verify')
@login_required
def verify_chain():
    blocks = BlockModel.query.order_by(BlockModel.index).all()
    tampered = False
    messages = []

    for i in range(1, len(blocks)):
        current = blocks[i]
        previous = blocks[i - 1]

        # Check previous hash matches
        if current.previous_hash != previous.block_hash:
            tampered = True
            messages.append(f"Block {current.index} previous hash mismatch.")

        # Recompute hash
        expected_hash = compute_hash(current.index, current.timestamp, current.evidence_hash, current.previous_hash, current.nonce, current.filename)
        if expected_hash != current.block_hash:
            tampered = True
            messages.append(f"Block {current.index} hash mismatch.")

        # Proof of Work check
        if not current.block_hash.startswith('0' * DIFFICULTY):
            tampered = True
            messages.append(f"Block {current.index} does not meet proof of work difficulty.")

    return render_template("verify.html", tampered=tampered, messages=messages)


if __name__ == '__main__':
    app.run(debug=True)
