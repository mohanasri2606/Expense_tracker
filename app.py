from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import bcrypt,os
from mysql.connector import Error
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '7389343c37dc054823ec06b9b2c1cf68db9536d5c1eff8715112d59a67159cb0')  

# Database connection function
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.environ.get('DB_HOST', 'maglev.proxy.rlwy.net'),  
            user=os.environ.get('DB_USER', 'root'),  
            port=os.environ.get('DB_PORT', '34359'),  
            password=os.environ.get('DB_PASSWORD', 'eckMkwQdwlMZokwJxNjcNFYmOIUYYhhJ'), 
            database=os.environ.get('DB_NAME', 'railway')  
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None


# Decorator to require login for certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Hash a password using bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check if the provided password matches the hashed password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login.html')

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            query = "SELECT id, password FROM users WHERE username = %s"
            cursor.execute(query, (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and check_password(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = username
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password.", "danger")
        else:
            flash("Database connection error.", "danger")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('register.html')

        hashed_password = hash_password(password)
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                query = "INSERT INTO users (username, password) VALUES (%s, %s)"
                cursor.execute(query, (username, hashed_password))
                conn.commit()
                flash("Registration successful! Please login.", "success")
                return redirect(url_for('login'))
            except Error as e:
                flash(f"Error during registration: {e}", "danger")
            finally:
                cursor.close()
                conn.close()
        else:
            flash("Database connection error.", "danger")
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    expenses = []
    total = 0
    if conn:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM expenses WHERE user_id = %s ORDER BY date DESC LIMIT 2"
        cursor.execute(query, (user_id,))
        expenses = cursor.fetchall()
        cursor.execute("SELECT SUM(amount) as total FROM expenses WHERE user_id = %s", (user_id,))
        total_result = cursor.fetchone()
        total = total_result['total'] if total_result['total'] else 0
        cursor.close()
        conn.close()
    return render_template('dashboard.html', expenses=expenses, total=total)

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    expense_name = request.form.get('expense_name', '').strip()
    amount = request.form.get('amount', '').strip()
    date = request.form.get('date', '').strip()
    user_id = session['user_id']

    if not expense_name or not amount or not date:
        flash("All fields are required.", "danger")
        return redirect(url_for('dashboard'))

    try:
        amount = float(amount)  # Ensure amount is a valid number
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            query = "INSERT INTO expenses (user_id, expense_name, amount, date) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (user_id, expense_name, amount, date))
            conn.commit()
            flash("Expense added successfully!", "success")
        except Error as e:
            flash(f"Error adding expense: {e}", "danger")
        finally:
            cursor.close()
            conn.close()
    else:
        flash("Database connection error.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    conn = get_db_connection()
    expense = None
    if conn:
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            expense_name = request.form.get('expense_name', '').strip()
            amount = request.form.get('amount', '').strip()
            date = request.form.get('date', '').strip()

            if not expense_name or not amount or not date:
                flash("All fields are required.", "danger")
                return redirect(url_for('dashboard'))

            try:
                amount = float(amount)  # Ensure amount is a valid number
            except ValueError:
                flash("Invalid amount. Please enter a valid number.", "danger")
                return redirect(url_for('dashboard'))

            try:
                query = "UPDATE expenses SET expense_name=%s, amount=%s, date=%s WHERE id=%s AND user_id=%s"
                cursor.execute(query, (expense_name, amount, date, expense_id, session['user_id']))
                conn.commit()
                flash("Expense updated successfully!", "success")
                return redirect(url_for('dashboard'))
            except Error as e:
                flash(f"Error updating expense: {e}", "danger")
        else:
            query = "SELECT * FROM expenses WHERE id=%s AND user_id=%s"
            cursor.execute(query, (expense_id, session['user_id']))
            expense = cursor.fetchone()
        cursor.close()
        conn.close()
    if not expense:
        flash("Expense not found or unauthorized access.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('edit_expense.html', expense=expense)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            query = "DELETE FROM expenses WHERE id=%s AND user_id=%s"
            cursor.execute(query, (expense_id, session['user_id']))
            conn.commit()
            flash("Expense deleted successfully!", "success")
        except Error as e:
            flash(f"Error deleting expense: {e}", "danger")
        finally:
            cursor.close()
            conn.close()
    else:
        flash("Database connection error.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.route('/manage_expenses')
@login_required
def manage_expenses():
    user_id = session.get('user_id')
    if not user_id:
        return "User not logged in", 401  

    conn = get_db_connection()
    expenses = []
    total = 0.0
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # ✅ Include 'id' in the SELECT query
        query = "SELECT id, expense_name, amount, date FROM expenses WHERE user_id = %s ORDER BY date DESC"
        cursor.execute(query, (user_id,))
        
        expenses = cursor.fetchall()

        # ✅ Print for debugging
        print("DEBUG: Expenses data:", expenses)  

        total = sum(expense['amount'] for expense in expenses)

        cursor.close()
        conn.close()
    
    return render_template('manage_expenses.html', expenses=expenses, total=total)

# Flash message with timestamp
def flash_with_timestamp(message, category="info"):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    flash((message, timestamp), category)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Use PORT if set, otherwise default to 5000
    app.run(host='0.0.0.0', port=port, debug=False)