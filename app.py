import os
import bcrypt
import jwt
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, g
from dotenv import load_dotenv

load_dotenv()

import datetime as _dt
from flask.json.provider import DefaultJSONProvider

class ISOJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, _dt.date) and not isinstance(o, _dt.datetime):
            return o.isoformat()
        if isinstance(o, _dt.datetime):
            return o.isoformat()
        return super().default(o)

app = Flask(__name__)
app.json = ISOJSONProvider(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')

DATABASE_URL = os.environ.get('DATABASE_URL', '')

# ── DB ─────────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        url = DATABASE_URL
        # Railway sometimes provides postgres:// instead of postgresql://
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        g.db = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
        g.db.autocommit = False
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def query(sql, params=(), one=False, commit=False):
    db = get_db()
    cur = db.cursor()
    cur.execute(sql, params)
    if commit:
        db.commit()
        return cur.rowcount
    result = cur.fetchone() if one else cur.fetchall()
    return result

# ── Auth middleware ────────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Init DB ────────────────────────────────────────────────────────────────────
def init_db():
    url = DATABASE_URL
    if not url:
        print('WARNING: No DATABASE_URL set')
        return
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    db = psycopg2.connect(url)
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ft_users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            trial_ends_at TIMESTAMP DEFAULT (NOW() + INTERVAL '30 days'),
            subscription_status VARCHAR(50) DEFAULT 'trial'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ft_slots (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES ft_users(id) ON DELETE CASCADE,
            date DATE NOT NULL,
            start_time VARCHAR(5),
            end_time VARCHAR(5),
            actual_end VARCHAR(5),
            gross NUMERIC(10,2) DEFAULT 0,
            tips NUMERIC(10,2) DEFAULT 0,
            timecomp NUMERIC(10,2) DEFAULT 0,
            odo_start INTEGER DEFAULT 0,
            odo_end INTEGER DEFAULT 0,
            other_expenses NUMERIC(10,2) DEFAULT 0,
            packages INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            cancelled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        ALTER TABLE ft_slots ADD COLUMN IF NOT EXISTS cancelled BOOLEAN DEFAULT FALSE
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ft_expenses (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES ft_users(id) ON DELETE CASCADE,
            date DATE NOT NULL,
            category VARCHAR(50) NOT NULL,
            amount NUMERIC(10,2) NOT NULL,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ft_returns (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES ft_users(id) ON DELETE CASCADE,
            date DATE NOT NULL,
            packages INTEGER NOT NULL,
            notes TEXT DEFAULT '',
            deadline VARCHAR(100),
            status VARCHAR(20) DEFAULT 'pending',
            ret_date DATE,
            ret_time VARCHAR(5),
            ret_odo_start INTEGER DEFAULT 0,
            ret_odo_end INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    db.commit()
    cur.close()
    db.close()
    print('DB initialised successfully')

# ── Pages ──────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/app')
def app_page():
    return render_template('app.html')

# ── Health ─────────────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    try:
        query('SELECT 1', one=True)
        db_ok = True
    except Exception as e:
        db_ok = False
    return jsonify({'status': 'ok', 'db': db_ok, 'app': 'FlexTrack'})

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        existing = query('SELECT id FROM ft_users WHERE email=%s', (email,), one=True)
        if existing:
            return jsonify({'error': 'Email already registered'}), 409
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        query('INSERT INTO ft_users (email, password_hash) VALUES (%s, %s)', (email, pw_hash), commit=True)
        user = query('SELECT * FROM ft_users WHERE email=%s', (email,), one=True)
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token, 'email': email, 'status': 'trial',
                        'trial_ends_at': user['trial_ends_at'].isoformat(),
                        'trial_days_left': 30})
    except Exception as e:
        print(f'Register error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        user = query('SELECT * FROM ft_users WHERE email=%s', (email,), one=True)
        if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({'error': 'Invalid email or password'}), 401
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        trial_ends = user['trial_ends_at']
        days_left = (trial_ends.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days if trial_ends else 0
        return jsonify({'token': token, 'email': email,
                        'status': user['subscription_status'],
                        'trial_ends_at': trial_ends.isoformat() if trial_ends else None,
                        'trial_days_left': max(0, days_left)})
    except Exception as e:
        print(f'Login error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/me', methods=['GET'])
@token_required
def me():
    user = query('SELECT id, email, created_at, trial_ends_at, subscription_status FROM ft_users WHERE id=%s',
                 (g.user_id,), one=True)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    trial_ends = user['trial_ends_at']
    days_left = (trial_ends.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days if trial_ends else 0
    return jsonify({**dict(user), 'trial_days_left': max(0, days_left),
                    'trial_ends_at': trial_ends.isoformat() if trial_ends else None,
                    'created_at': user['created_at'].isoformat() if user['created_at'] else None})

# ── Slots ──────────────────────────────────────────────────────────────────────
@app.route('/api/slots', methods=['GET'])
@token_required
def get_slots():
    rows = query('SELECT * FROM ft_slots WHERE user_id=%s ORDER BY date DESC, start_time DESC', (g.user_id,))
    return jsonify([dict(r) for r in rows])

@app.route('/api/slots', methods=['POST'])
@token_required
def add_slot():
    d = request.json
    query("""INSERT INTO ft_slots
             (user_id, date, start_time, end_time, actual_end, gross, tips, timecomp,
              odo_start, odo_end, other_expenses, packages, notes)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
          (g.user_id, d['date'], d.get('start',''), d.get('end',''), d.get('actual_end',''),
           d.get('gross',0), d.get('tips',0), d.get('timecomp',0),
           d.get('odo_start',0), d.get('odo_end',0), d.get('other',0),
           d.get('pkgs',0), d.get('notes','')), commit=True)
    row = query('SELECT * FROM ft_slots WHERE user_id=%s ORDER BY id DESC LIMIT 1', (g.user_id,), one=True)
    return jsonify(dict(row)), 201

@app.route('/api/slots/<int:slot_id>', methods=['PUT'])
@token_required
def update_slot(slot_id):
    d = request.json
    query("""UPDATE ft_slots SET date=%s, start_time=%s, end_time=%s, actual_end=%s,
             gross=%s, tips=%s, timecomp=%s, odo_start=%s, odo_end=%s,
             other_expenses=%s, packages=%s, notes=%s
             WHERE id=%s AND user_id=%s""",
          (d['date'], d.get('start',''), d.get('end',''), d.get('actual_end',''),
           d.get('gross',0), d.get('tips',0), d.get('timecomp',0),
           d.get('odo_start',0), d.get('odo_end',0), d.get('other',0),
           d.get('pkgs',0), d.get('notes',''), slot_id, g.user_id), commit=True)
    return jsonify({'ok': True})

@app.route('/api/slots/<int:slot_id>', methods=['DELETE'])
@token_required
def delete_slot(slot_id):
    query('DELETE FROM ft_slots WHERE id=%s AND user_id=%s', (slot_id, g.user_id), commit=True)
    return jsonify({'ok': True})

# ── Expenses ───────────────────────────────────────────────────────────────────
@app.route('/api/expenses', methods=['GET'])
@token_required
def get_expenses():
    rows = query('SELECT * FROM ft_expenses WHERE user_id=%s ORDER BY date DESC', (g.user_id,))
    return jsonify([dict(r) for r in rows])

@app.route('/api/expenses', methods=['POST'])
@token_required
def add_expense():
    d = request.json
    query('INSERT INTO ft_expenses (user_id, date, category, amount, notes) VALUES (%s,%s,%s,%s,%s)',
          (g.user_id, d['date'], d['category'], d['amount'], d.get('notes','')), commit=True)
    row = query('SELECT * FROM ft_expenses WHERE user_id=%s ORDER BY id DESC LIMIT 1', (g.user_id,), one=True)
    return jsonify(dict(row)), 201

@app.route('/api/expenses/<int:exp_id>', methods=['PUT'])
@token_required
def update_expense(exp_id):
    d = request.json
    query('UPDATE ft_expenses SET date=%s, category=%s, amount=%s, notes=%s WHERE id=%s AND user_id=%s',
          (d['date'], d['category'], d['amount'], d.get('notes',''), exp_id, g.user_id), commit=True)
    return jsonify({'ok': True})

@app.route('/api/expenses/<int:exp_id>', methods=['DELETE'])
@token_required
def delete_expense(exp_id):
    query('DELETE FROM ft_expenses WHERE id=%s AND user_id=%s', (exp_id, g.user_id), commit=True)
    return jsonify({'ok': True})

# ── Returns ────────────────────────────────────────────────────────────────────
@app.route('/api/returns', methods=['GET'])
@token_required
def get_returns():
    rows = query('SELECT * FROM ft_returns WHERE user_id=%s ORDER BY date DESC', (g.user_id,))
    return jsonify([dict(r) for r in rows])

@app.route('/api/returns', methods=['POST'])
@token_required
def add_return():
    d = request.json
    query('INSERT INTO ft_returns (user_id, date, packages, notes, deadline) VALUES (%s,%s,%s,%s,%s)',
          (g.user_id, d['date'], d['packages'], d.get('notes',''), d.get('deadline','')), commit=True)
    row = query('SELECT * FROM ft_returns WHERE user_id=%s ORDER BY id DESC LIMIT 1', (g.user_id,), one=True)
    return jsonify(dict(row)), 201

@app.route('/api/returns/<int:ret_id>', methods=['PUT'])
@token_required
def update_return(ret_id):
    d = request.json
    query("""UPDATE ft_returns SET date=%s, packages=%s, notes=%s, deadline=%s, status=%s,
             ret_date=%s, ret_time=%s, ret_odo_start=%s, ret_odo_end=%s
             WHERE id=%s AND user_id=%s""",
          (d['date'], d['packages'], d.get('notes',''), d.get('deadline',''),
           d.get('status','pending'), d.get('ret_date'), d.get('ret_time',''),
           d.get('ret_odo_start',0), d.get('ret_odo_end',0),
           ret_id, g.user_id), commit=True)
    return jsonify({'ok': True})

@app.route('/api/returns/<int:ret_id>', methods=['DELETE'])
@token_required
def delete_return(ret_id):
    query('DELETE FROM ft_returns WHERE id=%s AND user_id=%s', (ret_id, g.user_id), commit=True)
    return jsonify({'ok': True})

if __name__ == '__main__':
    if DATABASE_URL:
        init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1',
            host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
