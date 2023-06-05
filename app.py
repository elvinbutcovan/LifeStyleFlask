from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import relationship
import json
import re

SECRET_KEY = 'my_super_secure_secret_key_12345'

# Initialize Flask app, database, and CORS
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app)

# User model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=True)
    age = db.Column(db.Integer, nullable=True)
    weight = db.Column(db.Float, nullable=True)
    height = db.Column(db.Float, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    activityLevel = db.Column(db.String(10), nullable=True)

# DailyDiary model for database
class DailyDiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    water = db.Column(db.Float, nullable=False)
    sleep = db.Column(db.Float, nullable=False)
    calories = db.Column(db.Integer, nullable=False)
    exercises = db.Column(db.String, nullable=True)

    user = db.relationship('User', backref=db.backref('daily_diaries', lazy=True))

# Goals model for database
class Goals(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    waterGoal = db.Column(db.Float, nullable=False)
    sleepGoal = db.Column(db.Float, nullable=False)
    calorieGoal = db.Column(db.Integer, nullable=False)

    user = db.relationship('User', backref=db.backref('goals', lazy=True))

# Create tables in the database
with app.app_context():
    db.create_all()

# Function to validate password strength
def validate_password(password):
    min_length = 8
    has_uppercase = re.compile(r'[A-Z]')
    has_lowercase = re.compile(r'[a-z]')
    has_digit = re.compile(r'\d')
    has_special_char = re.compile(r'[^A-Za-z0-9]')

    return (
        len(password) >= min_length and
        len(password) <= 30 and
        bool(has_uppercase.search(password)) and
        bool(has_lowercase.search(password)) and
        bool(has_digit.search(password)) and
        bool(has_special_char.search(password))
    )

# Function to validate email format
def validate_email(email):
    email_regex = re.compile(r'^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$')
    return bool(email_regex.match(email))

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data['username']
    email = data['email']
    password = generate_password_hash(data['password'], method='sha256')
    confirm_password = data.get('confirmPassword')


    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'message': 'Username already exists'}), 409

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'message': 'Email already exists'}), 409
    
    # Validation
    if ('username' not in data or
        'email' not in data or
        'password' not in data):
        return jsonify({'message': 'Missing fields'}), 400
    
    if (not data['username'] or
        not data['email'] or
        not data['password'] or
        not confirm_password):
        return jsonify({'message': 'Empty fields'}), 400

    if (len(data['username']) > 30 or
        len(data['email']) > 60 or
        len(data['password']) > 30 or
        len(confirm_password) > 30) :
        return jsonify({'message': 'Invalid input'}), 400
    
    if not validate_password(data['password']):
        return jsonify({'message': 'Invalid password'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'message': 'Invalid email'}), 400
    
    if data['password'] != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 406

    new_user = User(username=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user is None or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY)

    return jsonify({'message': 'Logged in successfully', 'token': token, 'user_id': user.id}), 200

# Route for getting user profile data
@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404

    profile_data = {
        'id': user.id,
        'name': user.name,
        'age': user.age,
        'weight': user.weight,
        'height': user.height,
        'gender': user.gender,
        'activityLevel': user.activityLevel
    }
    return jsonify(profile_data), 200

# Route for updating user profile data
@app.route('/profile', methods=['POST'])
def update_profile():
    data = request.get_json()
    token = data.get('token')

    # Check for token existence in the data
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    # Decode the JWT token to get the user ID
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    # Handle exceptions related to JWT token
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Signature expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    # Get the user from the database based on the user_id
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    
    if (len(data['name']) < 2 or len(data['name']) > 50 or
        int(data['age']) < 10 or int(data['age']) > 120 or
        (data['gender'] not in ['male', 'female', 'other', ''] or data['gender'] == "Select Gender") or
        int(data['weight']) < 20 or int(data['weight']) > 500 or
        int(data['height']) < 50 or int(data['height']) > 300 or
        (data['activityLevel'] not in ['sedentary', 'light', 'moderate', 'active', 'very active', ''] or data['activityLevel'] == "Select Activity Level")) :
        return jsonify({'message': 'Invalid input'}), 400

    user.age = data.get('age', user.age)
    user.weight = data.get('weight', user.weight)
    user.height = data.get('height', user.height)
    user.name = data.get('name', user.name)
    user.gender = data.get('gender', user.gender)
    user.activityLevel = data.get('activityLevel', user.activityLevel)


    db.session.commit()

    return jsonify({
        'message': 'Profile updated successfully',
        'age': user.age,
        'weight': user.weight,
        'height': user.height,
        'name': user.name,
        'gender': user.gender,
        'activityLevel': user.activityLevel

    }), 200

# Route for changing user password
@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()

    token = data.get('token')
    user_id = data.get('userId')
    new_password = data.get('newPassword')
    confirm_new_password = data.get('confirmNewPassword')

    # Check for token existence in the data
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    if not new_password and confirm_new_password:
        return jsonify({'message': 'Please enter a new password'}), 405
    
    if new_password != confirm_new_password:
        return jsonify({'message': 'Passwords do not match'}), 406

    # Decode the JWT token to get the user ID
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # Handle exceptions related to JWT token
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Signature expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    if not user_id:
        return jsonify({'message': 'User ID is required'}), 403

    # Get the user from the database based on the user_id
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404

    # Validate the password using the custom validation function
    if not validate_password(new_password):
        return jsonify({'message': 'Invalid password'}), 400

    # Validate the password using the custom validation function
    hashed_password = generate_password_hash(new_password, method='sha256')
    user.password = hashed_password

    db.session.commit()

    return jsonify({'message': 'Password changed successfully'}), 200

# Route for deleting user profile
@app.route('/delete-profile/<int:user_id>', methods=['DELETE'])
def delete_profile(user_id):
    # Get the user from the database based on the user_id
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404

    # Delete all DailyDiary entries associated with the user
    DailyDiary.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    Goals.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200

# Route for adding or updating a daily diary entry
@app.route('/dailydiary', methods=['POST'])
def daily_diary():
    data = request.get_json()
    token = data.get('token')

    # Check for token existence in the data
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    # Decode the JWT token to get the user ID
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    # Handle exceptions related to JWT token
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Signature expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    # Get the user from the database based on the user_id
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404
    
    # Validate the submitted data
    if ('water' in data and (int(data['water']) < 0 or int(data['water']) > 10000) or
        'sleep' in data and (int(data['sleep']) < 0 or int(data['sleep']) > 1000) or
        'calories' in data and (int(data['calories']) < 0 or int(data['calories']) > 50000)):
        return jsonify({'message': 'Invalid input'}), 400

    for exercise in data['exercises']:
        if (len(exercise['name']) > 100 or
            len(exercise['bodyPart']) > 100 or
            int(exercise['reps']) < 0 or int(exercise['reps']) > 1000 or
        int(exercise['weight']) < 0 or int(exercise['weight']) > 1000):
            return jsonify({'message': 'Invalid exercise data'}), 400

    # Convert the date string to a datetime object
    date = datetime.strptime(data['date'], '%Y-%m-%d').date()
    water = data['water']
    sleep = data['sleep']
    calories = data['calories']
    exercises = data['exercises']

    # Check if a diary entry already exists for the given user ID and date
    daily_diary_entry = DailyDiary.query.filter_by(user_id=user_id, date=date).first()

    # If a daily diary entry does not exist, create a new entry; otherwise, update the existing entry
    if daily_diary_entry is None:
        daily_diary_entry = DailyDiary(user_id=user_id, date=date, water=water, sleep=sleep, calories=calories, exercises=json.dumps(exercises))
        db.session.add(daily_diary_entry)
    else:
        daily_diary_entry.water = water
        daily_diary_entry.sleep = sleep
        daily_diary_entry.calories = calories
        daily_diary_entry.exercises = json.dumps(exercises)

    db.session.commit()

    return jsonify({'message': 'Daily diary updated successfully'}), 200

# Route for getting a specific daily diary entry by user_id and date
@app.route('/dailydiary/<int:user_id>/<string:date_str>', methods=['GET'])
def get_daily_diary(user_id, date_str):

    # Convert the date string to a datetime object
    date = datetime.strptime(date_str, '%Y-%m-%d').date()
    # Check if a diary entry already exists for the given user ID and date
    daily_diary_entry = DailyDiary.query.filter_by(user_id=user_id, date=date).first()


    if daily_diary_entry:
        return jsonify({
            'water': daily_diary_entry.water,
            'sleep': daily_diary_entry.sleep,
            'calories': daily_diary_entry.calories,
            'exercises': daily_diary_entry.exercises 
        }), 200
    else:
        return jsonify({'message': 'Daily diary entry not found'}), 404

# Route for getting multiple daily diary entries within a given date range for a specific user
@app.route('/daily-diary', methods=['GET'])
def get_daily_diary_entries():
    user_id = request.args.get('userId')
    days = int(request.args.get('days', 7))

    if not user_id:
        return jsonify({'message': 'User ID is required'}), 400

    try:
        # Calculate the date range for fetching daily diary entries
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Fetch the daily diary entries within the specified date range for the given user ID
        entries = DailyDiary.query.filter(DailyDiary.user_id == user_id, DailyDiary.date.between(start_date, end_date)).order_by(DailyDiary.date).all()

        result = []
        for entry in entries:
            result.append({
                'date': entry.date.strftime('%Y-%m-%d'),
                'calories': entry.calories,
                'water': entry.water,
                'sleep':entry.sleep
            })

        return jsonify(result), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'Error fetching daily diary entries'}), 500
    
from datetime import datetime, timedelta

# Route for getting the averages of water, sleep, and calories from the last 7 days of daily diary entries for a specific user
@app.route('/dailydiary/averages/<int:user_id>', methods=['GET'])
def get_averages(user_id):
    today = datetime.utcnow().date()
    # Calculate the date for a week ago
    week_ago = today - timedelta(days=7)

    # Fetch the diary entries for the given user ID within the past week
    diary_entries = DailyDiary.query.filter_by(user_id=user_id).filter(DailyDiary.date >= week_ago).all()

    if diary_entries:
        total_water = 0
        total_sleep = 0
        total_calories = 0
        days_count = 0

        for entry in diary_entries:
            total_water += entry.water
            total_sleep += entry.sleep
            total_calories += entry.calories
            days_count += 1

        # Calculate the averages of water, sleep, and calories from the last 7 days of daily diary entries
        avg_water = total_water / days_count
        avg_sleep = total_sleep / days_count
        avg_calories = total_calories / days_count

        return jsonify({
            'avgWater': avg_water,
            'avgSleep': avg_sleep,
            'avgCalories': avg_calories,
        }), 200
    else:
        return jsonify({'message': 'No diary entries found in the last 7 days'}), 404

# Route for updating the goals (water, sleep, and calories) for a specific user
@app.route('/goals', methods=['POST'])
def update_goal():
    data = request.get_json()
    token = data.get('token')

    # Check for token existence in the data
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    # Decode the JWT token to get the user ID
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    # Handle exceptions related to JWT token
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Signature expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    # Get the user from the database based on the user_id
    user = db.session.get(User, user_id)

    # Check if the user exists, return a 404 error if not found
    if user is None:
        return jsonify({'message': 'User not found'}), 404

    # Validate the submitted data
    if ('waterGoal' in data and (int(data['waterGoal']) < 0 or int(data['waterGoal']) > 10000) or
        'sleepGoal' in data and (int(data['sleepGoal']) < 0 or int(data['sleepGoal']) > 1000) or
        'calorieGoal' in data and (int(data['calorieGoal']) < 0 or int(data['calorieGoal']) > 50000)):
        return jsonify({'message': 'Invalid input'}), 400

    waterGoal = data['waterGoal']
    sleepGoal = data['sleepGoal']
    calorieGoal = data['calorieGoal']

    # Check if a goal entry already exists for the given user ID
    goal_entry = Goals.query.filter_by(user_id=user_id).first()

    # If a goal entry does not exist, create a new entry; otherwise, update the existing entry
    if goal_entry is None:
        goal_entry = Goals(user_id=user_id, waterGoal=waterGoal, calorieGoal=calorieGoal, sleepGoal=sleepGoal)
        db.session.add(goal_entry)
    else:
        goal_entry.waterGoal = waterGoal
        goal_entry.sleepGoal = sleepGoal
        goal_entry.calorieGoal = calorieGoal

    db.session.commit()

    return jsonify({'message': 'Goals updated successfully'}), 200

# Route for getting the goals (water, sleep, and calories) for a specific user
@app.route('/goals/<int:user_id>', methods=['GET'])
def get_goals(user_id):
    goal_entry = Goals.query.filter_by(user_id=user_id).first()

    if goal_entry:
        return jsonify({
            'waterGoal': goal_entry.waterGoal,
            'sleepGoal': goal_entry.sleepGoal,
            'calorieGoal': goal_entry.calorieGoal,
        }), 200
    else:
        return jsonify({'message': 'Goals entry not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

