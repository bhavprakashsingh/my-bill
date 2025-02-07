from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# CORS(app)  # Enable CORS for API calls

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback_secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///billing.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback_jwt_secret")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Billing Model
class BillingRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    items = db.Column(db.Text, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

# Initialize DB
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    # token = session.get("token")
    # if not token:
    #     return redirect(url_for("home.html"))  # Redirect to login if no token

    # user_id = get_jwt_identity()
    # user = User.query.get(user_id)
    return render_template("home.html")  # Render Home Page with username

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(hours=1))
            session["token"] = token  # Store token in session
            response = redirect(url_for("home"))  # Redirect to dashboard
            response.set_cookie("access_token_cookie", token)  # Set JWT cookies
            return response

        return jsonify({"error": "Invalid Credentials"}), 401

    return render_template("login.html")  # Render login form for GET requests

@app.route("/dashboard")
@jwt_required()  # Ensure the route requires a valid JWT token
def dashboard():
    try:
        verify_jwt_in_request()  # Verify JWT in request
        user_id = get_jwt_identity()  # Get user ID from token
        print(f"User ID from token: {user_id}")  # Debugging statement

        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        customer_name = request.args.get("customer_name")

        query = BillingRecord.query.filter_by(user_id=user_id)
        if start_date:
            query = query.filter(BillingRecord.date >= start_date)
        if end_date:
            query = query.filter(BillingRecord.date <= end_date)
        if customer_name:
            query = query.filter(BillingRecord.customer_name.ilike(f"%{customer_name}%"))

        records = query.all()
        return render_template("dashboard.html", records=records)
    except Exception as e:
        print(f"Error: {e}")  # Debugging statement
        return redirect(url_for("login"))

@app.route("/add_bill", methods=["GET", "POST"])
@jwt_required()
def add_bill():
    user_id = get_jwt_identity()  # Get user ID from token

    if request.method == "POST":
        # Get form data
        date = request.form.get("date")
        customer_name = request.form.get("customer_name")
        item_names = request.form.getlist("item_name[]")  # Ensure [] matches the form
        item_prices = request.form.getlist("item_price[]")

        # Validate required fields
        if not date or not customer_name or not item_names or not item_prices:
            flash("All fields are required!", "danger")
            return redirect(url_for("add_bill"))

        # Ensure all items have valid prices
        items_list = []
        total_price = 0.0

        try:
            for name, price in zip(item_names, item_prices):
                price = float(price)  # Convert to float
                items_list.append(f"{name}:{price}")
                total_price += price
        except ValueError:
            flash("Invalid price entered!", "danger")
            return redirect(url_for("add_bill"))

        # Convert date to proper format
        try:
            date = datetime.datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format!", "danger")
            return redirect(url_for("add_bill"))

        # Save to database
        new_bill = BillingRecord(
            user_id=user_id,
            date=date,
            customer_name=customer_name,
            items=",".join(items_list),  # Store as a single string
            total_price=total_price,
        )

        db.session.add(new_bill)
        db.session.commit()

        flash("Bill added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_bill.html")

@app.route("/logout")
def logout():
    session.pop("token", None)  # Remove token from session
    response = redirect(url_for("login"))  # Redirect to login
    unset_jwt_cookies(response)  # Unset JWT cookies
    return response

# Ensure the Flask app runs
if __name__ == "__main__":
    app.run()
