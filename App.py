import re
from flask import Flask, render_template, url_for, request, redirect, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

client = MongoClient('localhost', 27017)
db = client.flask_database
todos = db.todos
users = db.users
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
@app.route("/", methods=['GET', 'POST'])
def index():
    if 'username' in session:
        if request.method == 'POST':
            content = request.form['content']
            degree = request.form['degree']
            todos.insert_one({'content': content, 'degree': degree, 'username': session['username']})
            return redirect(url_for('index'))
        all_todos = todos.find({'username': session['username']})
        return render_template('index.html', todos=all_todos)
    return redirect(url_for('login'))

@app.route("/<id>/delete/", methods=['POST'])
def delete(id):
    todos.delete_one({"_id": ObjectId(id), 'username': session['username']})
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
      if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        if users.find_one({'username': username}):
            flash('Username already taken, please choose another one.')
            return render_template('register.html')
        
        # Validate password length and complexity
        if not PASSWORD_REGEX.match(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, digits, and special characters.')
            return render_template('register.html')
        
        # Proceed with registration
        hashed_password = generate_password_hash(password)
        users.insert_one({'username': username, 'password': hashed_password})
        session['username'] = username
        return redirect(url_for('index'))
    
      return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        # Validate password length and complexity
        if not PASSWORD_REGEX.match(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, digits, and special characters.')
            return render_template('login.html')
        
        user = users.find_one({'$or': [{'username': identifier}, {'email': identifier}]})
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            return redirect(url_for('index'))
        flash('Invalid username or email or password')
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
