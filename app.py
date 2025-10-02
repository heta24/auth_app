import pyotp
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------- Flask Setup -------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# Mail config (server email)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "2faflaskapp@gmail.com"       # <-- your server Gmail
app.config['MAIL_PASSWORD'] = "vexu fwbx ldbs aygn" # <-- App Password
mail = Mail(app)

# ------------------- DB Model -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

with app.app_context():
    db.create_all()

# ------------------- Routes -------------------
@app.route('/')
def index():
    if "user" in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

# ------------------- REGISTER -------------------
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        otp_secret = pyotp.random_base32()

        user = User(username=username, email=email, password=password, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        flash("✅ Registration successful! You can now login.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")

# ------------------- LOGIN -------------------
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["username"] = user.username
            return redirect(url_for("choose_2fa"))
        else:
            flash("❌ Invalid username or password", "error")
    return render_template("login.html")

# ------------------- CHOOSE 2FA -------------------
@app.route('/choose_2fa')
def choose_2fa():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("choose_2fa.html")

# ------------------- EMAIL OTP -------------------
@app.route('/otp', methods=["GET", "POST"])
def otp_verify():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    totp = pyotp.TOTP(user.otp_secret, interval=120)  # 2-min OTP
    otp = totp.now()

    # Send OTP
    msg = Message("Your OTP",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)
    flash(f"OTP sent to {user.email}", "info")

    if request.method == "POST":
        entered = request.form["otp"]
        if totp.verify(entered):
            session["user"] = user.username
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid OTP", "error")
    return render_template("otp.html")

# ------------------- HOME -------------------
@app.route('/home')
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("home.html", user=session["user"])

# ------------------- LOGOUT -------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------- RUN APP -------------------
if __name__ == "__main__":
    app.run(debug=True)
