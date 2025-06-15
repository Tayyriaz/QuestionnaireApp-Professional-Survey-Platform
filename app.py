from flask import Flask, render_template, request, redirect, g, session, flash, url_for, send_file
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
import csv
from io import StringIO, BytesIO
from datetime import datetime, timedelta
import secrets
import click

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret in production
DATABASE = 'project.db'
UPLOAD_FOLDER = 'uploads'

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db_logic():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        
        # Drop existing tables if they exist
        c.execute('DROP TABLE IF EXISTS users')
        c.execute('DROP TABLE IF EXISTS items')
        c.execute('DROP TABLE IF EXISTS questions')
        c.execute('DROP TABLE IF EXISTS responses')

        # Create users table
        c.execute('''
            CREATE TABLE users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL,
              is_admin INTEGER DEFAULT 0,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              reset_token TEXT,
              reset_token_expiration TIMESTAMP
            )
        ''')
        
        # Create a default admin user
        c.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                  ('admin', 'admin@example.com', generate_password_hash('admin'), 1))

        # Create items table
        c.execute('''CREATE TABLE items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            explanation TEXT,
            video_path TEXT,
            image_path TEXT
        )''')
        # Questions table
        c.execute('''CREATE TABLE questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            code TEXT,
            text TEXT NOT NULL,
            type TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES items(id)
        )''')
        # Responses table
        c.execute('''CREATE TABLE responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            value TEXT,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES items(id),
            FOREIGN KEY (question_id) REFERENCES questions(id)
        )''')
        
        db.commit()

@app.cli.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db_logic()
    click.echo('Initialized the database.')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/db_test')
def db_test():
    try:
        db = get_db()
        c = db.cursor()
        c.execute('SELECT name FROM sqlite_master WHERE type="table";')
        tables = c.fetchall()
        return f"Connected! Tables: {tables}"
    except Exception as e:
        return f"Database connection failed: {e}"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        try:
            c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                      (username, email, generate_password_hash(password)))
            db.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        c.execute('SELECT * FROM users WHERE email=?', (email,))
        user = c.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Login successful!', 'success')
            return redirect(url_for('welcome'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        c = db.cursor()
        c.execute('SELECT * FROM users WHERE email=? AND is_admin=1', (email,))
        user = c.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid or unauthorized admin credentials.', 'danger')
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def welcome():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM items')
    items = c.fetchall()
    return render_template('welcome.html', items=items)

# Admin login required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required. Please log in.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM items')
    items = c.fetchall()

    # Fetch all submissions for the new tab
    c.execute('''
        SELECT
            u.username,
            i.name as item_name,
            r.timestamp,
            SUM(CAST(r.value AS INTEGER)) as score
        FROM responses r
        JOIN users u ON r.user_id = u.id
        JOIN items i ON r.item_id = i.id
        GROUP BY r.user_id, u.username, i.name, r.timestamp
        ORDER BY r.timestamp DESC
    ''')
    all_submissions_raw = c.fetchall()

    # Manually convert timestamp string to datetime object
    all_submissions = []
    for row in all_submissions_raw:
        row_dict = dict(row)
        if isinstance(row_dict.get('timestamp'), str):
            row_dict['timestamp'] = datetime.fromisoformat(row_dict['timestamp'])
        all_submissions.append(row_dict)

    # If no items exist, create a demo item and question
    if not items:
        c.execute('INSERT INTO items (name, description) VALUES (?, ?)',
                  ('Demo Item', 'This is a demo item. You can delete or edit it.'))
        db.commit()
        c.execute('SELECT id FROM items WHERE name=?', ('Demo Item',))
        demo_item_id = c.fetchone()[0]
        c.execute('INSERT INTO questions (item_id, code, text, type) VALUES (?, ?, ?, ?)',
                  (demo_item_id, 'demo_q1', 'Is this a demo?', 'yesno'))
        db.commit()
        c.execute('SELECT * FROM items')
        items = c.fetchall()
    return render_template('admin_dashboard.html', items=items, submissions=all_submissions)

@app.route('/admin/add_item', methods=['GET', 'POST'])
@admin_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        explanation = request.form.get('explanation')
        video = request.files.get('video')
        image = request.files.get('image')
        video_path = None
        image_path = None
        if video and video.filename:
            video_filename = secure_filename(video.filename)
            video.save(os.path.join('static', video_filename))
            video_path = f'static/{video_filename}'
        if image and image.filename:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join('static', image_filename))
            image_path = f'static/{image_filename}'
        db = get_db()
        c = db.cursor()
        c.execute('INSERT INTO items (name, description, explanation, video_path, image_path) VALUES (?, ?, ?, ?, ?)',
                  (name, description, explanation, video_path, image_path))
        db.commit()
        flash('Item added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_item.html')

@app.route('/admin/edit_item/<int:item_id>', methods=['GET', 'POST'])
@admin_required
def edit_item(item_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM items WHERE id=?', (item_id,))
    item = c.fetchone()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        explanation = request.form.get('explanation')
        video = request.files.get('video')
        image = request.files.get('image')
        video_path = item['video_path']
        image_path = item['image_path']
        if video and video.filename:
            video_filename = secure_filename(video.filename)
            video.save(os.path.join('static', video_filename))
            video_path = f'static/{video_filename}'
        if image and image.filename:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join('static', image_filename))
            image_path = f'static/{image_filename}'
        c.execute('UPDATE items SET name=?, description=?, explanation=?, video_path=?, image_path=? WHERE id=?',
                  (name, description, explanation, video_path, image_path, item_id))
        db.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_item.html', item=item)

@app.route('/admin/delete_item/<int:item_id>', methods=['POST'])
@admin_required
def delete_item(item_id):
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM items WHERE id=?', (item_id,))
    db.commit()
    flash('Item deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Admin: Manage questions for each item
@app.route('/admin/item/<int:item_id>/questions')
@admin_required
def manage_questions(item_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM items WHERE id=?', (item_id,))
    item = c.fetchone()
    c.execute('SELECT * FROM questions WHERE item_id=?', (item_id,))
    questions = c.fetchall()
    return render_template('manage_questions.html', item=item, questions=questions)

@app.route('/admin/item/<int:item_id>/add_question', methods=['GET', 'POST'])
@admin_required
def add_question(item_id):
    db = get_db()
    c = db.cursor()

    if request.method == 'POST':
        code = request.form['code']
        text = request.form['text']
        qtype = request.form['type']
        c.execute('INSERT INTO questions (item_id, code, text, type) VALUES (?, ?, ?, ?)',
                  (item_id, code, text, qtype))
        db.commit()
        flash('Question added!', 'success')
        return redirect(url_for('manage_questions', item_id=item_id))

    # For GET request, fetch the item details
    c.execute('SELECT * FROM items WHERE id = ?', (item_id,))
    item = c.fetchone()
    if item is None:
        flash('Item not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_question.html', item_id=item_id, item=item)

@app.route('/admin/item/<int:item_id>/edit_question/<int:question_id>', methods=['GET', 'POST'])
@admin_required
def edit_question(item_id, question_id):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM questions WHERE id=?', (question_id,))
    question = c.fetchone()
    if request.method == 'POST':
        code = request.form['code']
        text = request.form['text']
        qtype = request.form['type']
        c.execute('UPDATE questions SET code=?, text=?, type=? WHERE id=?',
                  (code, text, qtype, question_id))
        db.commit()
        flash('Question updated!', 'success')
        return redirect(url_for('manage_questions', item_id=item_id))
    return render_template('edit_question.html', item_id=item_id, question=question)

@app.route('/admin/item/<int:item_id>/delete_question/<int:question_id>', methods=['POST'])
@admin_required
def delete_question(item_id, question_id):
    db = get_db()
    c = db.cursor()
    c.execute('DELETE FROM questions WHERE id=?', (question_id,))
    db.commit()
    flash('Question deleted!', 'success')
    return redirect(url_for('manage_questions', item_id=item_id))

def answer_to_numeric(qtype, answer):
    if qtype == 'yesno':
        return '1' if answer == 'Yes' else '0'
    return answer

# User: Shop and questionnaire flow
@app.route('/item/<int:item_id>', methods=['GET', 'POST'])
def item_questionnaire(item_id):
    if session.get('is_admin'):
        flash("Admins cannot submit questionnaires. Please use a regular user account.", 'warning')
        return redirect(url_for('admin_dashboard'))
    if 'user_id' not in session:
        flash('Please log in to answer questions.', 'warning')
        return redirect(url_for('login'))
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM items WHERE id=?', (item_id,))
    item = c.fetchone()
    c.execute('SELECT * FROM questions WHERE item_id=?', (item_id,))
    questions = c.fetchall()
    if request.method == 'POST':
        # Check if at least one answer was submitted
        if not any(request.form.get(f"q_{q['id']}") for q in questions):
            flash("You must answer at least one question to submit.", 'warning')
            return redirect(url_for('item_questionnaire', item_id=item_id))

        # First, clear any previous responses for this user and item to ensure data is fresh.
        c.execute('DELETE FROM responses WHERE user_id = ? AND item_id = ?',
                  (session['user_id'], item_id))
        
        submission_time = datetime.utcnow()
        for q in questions:
            answer = request.form.get(f"q_{q['id']}")
            # Only insert a response if an answer was provided
            if answer is not None:
                numeric_answer = answer_to_numeric(q['type'], answer)
                c.execute('INSERT INTO responses (user_id, item_id, question_id, value, timestamp) VALUES (?, ?, ?, ?, ?)',
                          (session['user_id'], item_id, q['id'], numeric_answer, submission_time))
        db.commit()
        flash('Your answers have been submitted!', 'success')
        return redirect(url_for('results'))
    return render_template('item_questionnaire.html', item=item, questions=questions)

@app.route('/admin/export_responses')
@admin_required
def export_responses():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT users.username, items.name, questions.code, questions.text, responses.value
                 FROM responses
                 JOIN users ON responses.user_id = users.id
                 JOIN items ON responses.item_id = items.id
                 JOIN questions ON responses.question_id = questions.id
                 ORDER BY responses.id''')
    rows = c.fetchall()
    
    # Use an in-memory stream for the CSV data
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Username', 'Item', 'Question Code', 'Question Text', 'Answer'])
    writer.writerows(rows)
    
    # Prepare the buffer to send the file
    buffer = BytesIO(si.getvalue().encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name='responses.csv'
    )

@app.route('/results')
def results():
    if 'user_id' not in session:
        flash('Please log in to view your results.', 'warning')
        return redirect(url_for('login'))
    db = get_db()
    c = db.cursor()
    c.execute('''
        SELECT
            i.name as item_name,
            u.username as username,
            r.timestamp,
            SUM(CAST(r.value AS INTEGER)) as score
        FROM responses r
        JOIN users u ON r.user_id = u.id
        JOIN items i ON r.item_id = i.id
        WHERE r.user_id = ?
        GROUP BY r.user_id, u.username, i.name, r.timestamp
        ORDER BY r.timestamp DESC
    ''', (session['user_id'],))
    results_raw = c.fetchall()

    # Manually convert timestamp string to datetime object because sqlite can be quirky
    results = []
    for row in results_raw:
        row_dict = dict(row)
        if isinstance(row_dict.get('timestamp'), str):
            row_dict['timestamp'] = datetime.fromisoformat(row_dict['timestamp'])
        results.append(row_dict)
        
    return render_template('results.html', results=results)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        c = db.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        if user:
            token = secrets.token_urlsafe(16)
            expiration = datetime.utcnow() + timedelta(hours=1)
            # In a real app, you would store this in a dedicated tokens table
            c.execute('UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE id = ?',
                      (token, expiration, user['id']))
            db.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            # In a real app, you'd email this link. For a demo, we'll flash it.
            flash(f'Password reset link generated. For demo purposes, click here: {reset_url}', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM users WHERE reset_token = ?', (token,))
    user = c.fetchone()

    if not user or user['reset_token_expiration'] < datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
        if password != password_confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        hashed_password = generate_password_hash(password)
        c.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE id = ?',
                  (hashed_password, user['id']))
        db.commit()
        flash('Your password has been updated successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# More routes and logic will be added here for authentication, admin, questionnaire, etc.

if __name__ == '__main__':
    app.run(debug=True, port=5003) 