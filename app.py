# This file will implement the endpoints described in your Step 2 and Step 3 prompt
# It will contain CRUD operations for /users and /projects
# Using raw SQL queries and Flask

from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'port': os.getenv('DB_PORT')
}

app = Flask(__name__)
CORS(app)

# JWT Secret Key - should be in environment variables in production
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-this')

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user_id, *args, **kwargs)
    return decorated
    
# Health check
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'API is working'}), 200

# Root route
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Task Management API'}), 200

# -------- AUTHENTICATION ENDPOINTS --------

@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username') or data.get('name')  # Support both 'name' and 'username'
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'error': 'Username, email, and password are required'}), 400

    # Check if user already exists
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        # Check if email already exists
        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400

        # Create new user
        hashed_password = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id, username, email',
            (username, email, hashed_password)
        )
        user = cursor.fetchone()
        conn.commit()

        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'user': {
                'id': user['id'],
                'name': user['username'],
                'email': user['email']
            },
            'token': token
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/auth/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        # Find user by email
        cursor.execute('SELECT id, username, email, password FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'user': {
                'id': user['id'],
                'name': user['username'],
                'email': user['email']
            },
            'token': token
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, email FROM users WHERE id = %s', (current_user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify({
                'user': {
                    'id': user['id'],
                    'name': user['username'],
                    'email': user['email']
                }
            }), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------- TASK ENDPOINTS --------

# GET all tasks
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        # Get tasks with project and user info
        cursor.execute('''
            SELECT 
                t.*,
                p.name as project_name,
                u.username as assigned_user_name
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.user_id = %s OR t.user_id IS NULL
        ''', (current_user_id,))
        tasks = cursor.fetchall()
        return jsonify(tasks), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# GET a single task with details
@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task_details(current_user_id, task_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        # Get task with project and user details
        cursor.execute('''
            SELECT 
                t.*,
                p.name as project_name,
                p.description as project_description,
                p.status as project_status,
                u.username as assigned_user_name,
                u.email as assigned_user_email
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s AND (t.user_id = %s OR t.user_id IS NULL)
        ''', (task_id, current_user_id))
        task = cursor.fetchone()
        
        if task:
            return jsonify(task), 200
        else:
            return jsonify({'error': 'Task not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# CREATE a new task
@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    project_id = data.get('project_id')
    user_id = data.get('user_id', current_user_id)
    priority = data.get('priority', 'medium')  # Default to medium priority

    if not title:
        return jsonify({'error': 'Title is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO tasks (title, description, project_id, user_id, priority) VALUES (%s, %s, %s, %s, %s) RETURNING *',
            (title, description, project_id, user_id, priority)
        )
        new_task = cursor.fetchone()
        conn.commit()
        return jsonify(new_task), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# UPDATE a task
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user_id, task_id):
    data = request.get_json()
    
    # Build dynamic update fields
    fields = []
    values = []
    
    for field in ['title', 'description', 'project_id', 'user_id', 'priority', 'status']:
        if field in data:
            fields.append(f"{field} = %s")
            values.append(data[field])
    
    if not fields:
        return jsonify({'error': 'No fields to update'}), 400
    
    values.append(task_id)
    values.append(current_user_id)

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute(
            f'UPDATE tasks SET {", ".join(fields)} WHERE id = %s AND (user_id = %s OR user_id IS NULL) RETURNING *',
            tuple(values)
        )
        updated_task = cursor.fetchone()
        conn.commit()
        if updated_task:
            return jsonify(updated_task), 200
        else:
            return jsonify({'error': 'Task not found or unauthorized'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# DELETE a task
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user_id, task_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM tasks WHERE id = %s AND (user_id = %s OR user_id IS NULL) RETURNING *', (task_id, current_user_id))
        deleted_task = cursor.fetchone()
        conn.commit()
        if deleted_task:
            return jsonify({'message': 'Task deleted successfully'}), 200
        else:
            return jsonify({'error': 'Task not found or unauthorized'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------- USER ENDPOINTS --------

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'error': 'Username, email, and password are required'}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id, username, email',
            (username, email, hashed_password)
        )
        user = cursor.fetchone()
        conn.commit()
        return jsonify(user), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, email FROM users')
        users = cursor.fetchall()
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user_id, user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, username, email FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify(user), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user_id, user_id):
    # Users can only update their own profile
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    fields = []
    values = []
    for field in ['username', 'email', 'password']:
        if field in data:
            fields.append(f"{field} = %s")
            if field == 'password':
                values.append(generate_password_hash(data[field]))
            else:
                values.append(data[field])

    if not fields:
        return jsonify({'error': 'No fields to update'}), 400

    values.append(user_id)
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = %s RETURNING id, username, email", tuple(values))
        updated_user = cursor.fetchone()
        conn.commit()
        if updated_user:
            return jsonify(updated_user), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user_id, user_id):
    # Users can only delete their own account
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        # Optionally: DELETE user tasks/projects or set user_id to NULL first
        cursor.execute('DELETE FROM users WHERE id = %s RETURNING id', (user_id,))
        deleted_user = cursor.fetchone()
        conn.commit()
        if deleted_user:
            return jsonify({'message': 'User deleted successfully'}), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# -------- PROJECT ENDPOINTS --------

@app.route('/projects', methods=['POST'])
@token_required
def create_project(current_user_id):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    status = data.get('status')

    # Validate all fields
    if not all([name, description, status]):
        return jsonify({'error': 'Name, description, and status are required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO projects (name, description, status, user_id) VALUES (%s, %s, %s, %s) RETURNING *',
            (name, description, status, current_user_id)
        )

        project = cursor.fetchone()
        conn.commit()
        return jsonify(project), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/projects', methods=['GET'])
@token_required
def get_projects(current_user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM projects')
        projects = cursor.fetchall()
        return jsonify(projects), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/projects/<int:project_id>', methods=['GET'])
@token_required
def get_project(current_user_id, project_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM projects WHERE id = %s', (project_id,))
        project = cursor.fetchone()
        if project:
            return jsonify(project), 200
        else:
            return jsonify({'error': 'Project not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# NEW: Get project details with tasks and members
@app.route('/projects/<int:project_id>/details', methods=['GET'])
@token_required
def get_project_details(current_user_id, project_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    try:
        # Get project info
        cursor.execute('SELECT * FROM projects WHERE id = %s', (project_id,))
        project = cursor.fetchone()
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Get tasks associated with this project
        cursor.execute('''
            SELECT 
                t.*,
                u.username as assigned_user_name,
                u.email as assigned_user_email
            FROM tasks t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.project_id = %s
            ORDER BY t.created_at DESC
        ''', (project_id,))
        tasks = cursor.fetchall()
        
        # Get unique members assigned to tasks in this project
        cursor.execute('''
            SELECT DISTINCT u.id, u.username, u.email
            FROM users u
            INNER JOIN tasks t ON u.id = t.user_id
            WHERE t.project_id = %s
        ''', (project_id,))
        members = cursor.fetchall()
        
        # Calculate project statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_tasks,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_tasks,
                COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_tasks,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks
            FROM tasks 
            WHERE project_id = %s
        ''', (project_id,))
        stats = cursor.fetchone()
        
        return jsonify({
            'project': project,
            'tasks': tasks,
            'members': members,
            'statistics': stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/projects/<int:project_id>', methods=['PUT'])
@token_required
def update_project(current_user_id, project_id):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    status = data.get('status')

    # Build dynamic SQL update fields
    fields = []
    values = []

    if name is not None:
        fields.append("name = %s")
        values.append(name)
    if description is not None:
        fields.append("description = %s")
        values.append(description)
    if status is not None:
        fields.append("status = %s")
        values.append(status)

    if not fields:
        return jsonify({'error': 'No fields to update'}), 400

    # Add WHERE clause values
    values.append(project_id)       # WHERE id = %s
    values.append(current_user_id)  # AND user_id = %s

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        query = f"""
            UPDATE projects
            SET {', '.join(fields)}
            WHERE id = %s AND user_id = %s
            RETURNING *
        """
        cursor.execute(query, tuple(values))
        updated_project = cursor.fetchone()
        conn.commit()

        if updated_project:
            return jsonify(updated_project), 200
        else:
            return jsonify({'error': 'Project not found or unauthorized'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route('/projects/<int:project_id>', methods=['DELETE'])
@token_required
def delete_project(current_user_id, project_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM projects WHERE id = %s RETURNING *', (project_id,))
        deleted_project = cursor.fetchone()
        conn.commit()
        if deleted_project:
            return jsonify({'message': 'Project deleted successfully'}), 200
        else:
            return jsonify({'error': 'Project not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)