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
import stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PRICE_ID = os.environ.get('STRIPE_PRICE_ID', 'price_1TuyM5CRmG5p6ItKOPWycQjh')
STRIPE_ANNUAL_PRICE_ID = os.environ.get('STRIPE_ANNUAL_PRICE_ID', 'price_1TwLtZCRmG5p6ItKVwjKgyYy')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')

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
            trial_ends_at TIMESTAMP DEFAULT (NOW() + INTERVAL '7 days'),
            subscription_status VARCHAR(50) DEFAULT 'trial',
            stripe_customer_id VARCHAR(255),
            stripe_subscription_id VARCHAR(255),
            hr_rate NUMERIC(5,2) DEFAULT 1.49
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
        ALTER TABLE ft_users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)
    """)
    cur.execute("""
        ALTER TABLE ft_users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)
    """)
    cur.execute("""
        ALTER TABLE ft_users ADD COLUMN IF NOT EXISTS hr_rate NUMERIC(5,2) DEFAULT 1.49
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
        # Send welcome email to new driver
        try:
            welcome_lines = [
                "Hi there,",
                "",
                "Welcome to FlexLog! Your 7-day free trial has started.",
                "",
                "Here is how to get started:",
                "",
                "1. LOG YOUR SLOTS",
                "   Tap Log slot, enter date, times and odometer readings.",
                "   FlexLog calculates mileage, H&R insurance and net profit automatically.",
                "",
                "2. LOG YOUR EXPENSES",
                "   Add fuel, MOT, insurance, tyres -- anything you spend on the car.",
                "   These appear in your Actual Cash report (separate from HMRC figures).",
                "",
                "3. CHECK YOUR REPORTS",
                "   Tax/UC tab shows HMRC SA103 and Universal Credit monthly earnings.",
                "   Reports tab shows charts and sortable slot breakdown.",
                "",
                "4. SET YOUR H&R RATE",
                "   Tap the gear icon (top right) and enter your H&R insurance rate per hour.",
                "   Default is 1.49/hr -- update it to match your actual policy.",
                "",
                "Your trial runs for 7 days. After that it is just 3 per month -- cancel anytime.",
                "",
                "Any questions? Reply to this email and I will help personally.",
                "",
                "Good luck out there,",
                "MRAhmed",
                "FlexLog -- flexlog.co.uk",
                "support@flexlog.co.uk"
            ]
            welcome_body = "\n".join(welcome_lines)
            send_email(email, "Welcome to FlexLog -- here is how to get started", welcome_body)
        except Exception as ne:
            print(f'Welcome email failed: {ne}')
                # Send notification email to admin
        try:
            send_admin_notification(email, 'New trial signup')
        except Exception as ne:
            print(f'Notification email failed: {ne}')
        return jsonify({'token': token, 'email': email, 'status': 'trial',
                        'trial_ends_at': user['trial_ends_at'].isoformat(),
                        'trial_days_left': 7})
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
    return jsonify({**dict(user), 'trial_days_left': max(0, days_left), 'hr_rate': float(user.get('hr_rate') or 1.49),
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
    cancelled = bool(d.get('cancelled', False))
    query("""INSERT INTO ft_slots
             (user_id, date, start_time, end_time, actual_end, gross, tips, timecomp,
              odo_start, odo_end, other_expenses, packages, notes, cancelled)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
          (g.user_id, d['date'], d.get('start',''), d.get('end',''), d.get('actual_end',''),
           d.get('gross',0), d.get('tips',0), d.get('timecomp',0),
           d.get('odo_start',0) if not cancelled else 0,
           d.get('odo_end',0) if not cancelled else 0,
           d.get('other',0), d.get('pkgs',0), d.get('notes',''), cancelled), commit=True)
    row = query('SELECT * FROM ft_slots WHERE user_id=%s ORDER BY id DESC LIMIT 1', (g.user_id,), one=True)
    return jsonify(dict(row)), 201

@app.route('/api/slots/<int:slot_id>', methods=['PUT'])
@token_required
def update_slot(slot_id):
    d = request.json
    cancelled = bool(d.get('cancelled', False))
    query("""UPDATE ft_slots SET date=%s, start_time=%s, end_time=%s, actual_end=%s,
             gross=%s, tips=%s, timecomp=%s, odo_start=%s, odo_end=%s,
             other_expenses=%s, packages=%s, notes=%s, cancelled=%s
             WHERE id=%s AND user_id=%s""",
          (d['date'], d.get('start',''), d.get('end',''), d.get('actual_end',''),
           d.get('gross',0), d.get('tips',0), d.get('timecomp',0),
           d.get('odo_start',0) if not cancelled else 0,
           d.get('odo_end',0) if not cancelled else 0,
           d.get('other',0), d.get('pkgs',0), d.get('notes',''), cancelled,
           slot_id, g.user_id), commit=True)
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

# ── Email helpers ─────────────────────────────────────────────────────────────
def send_email(to_email, subject, body_text):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    smtp_host = os.environ.get('SMTP_HOST', 'mail.privateemail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 465))
    smtp_user = os.environ.get('SMTP_USER', 'support@flexlog.co.uk')
    smtp_pass = os.environ.get('SMTP_PASS', '')
    if not smtp_pass:
        print(f'SMTP_PASS not set, skipping email to {to_email}')
        return False
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f'FlexLog <{smtp_user}>'
    msg['To'] = to_email
    msg.attach(MIMEText(body_text, 'plain'))
    with smtplib.SMTP_SSL(smtp_host, smtp_port) as s:
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
    print(f'Email sent to {to_email}: {subject}')
    return True

def send_admin_notification(user_email, event):
    send_email(
        os.environ.get('SMTP_USER', 'support@flexlog.co.uk'),
        f'FlexLog: {event} -- {user_email}',
        f'{event}\n\nUser: {user_email}\nTime: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}'
    )

# ── Trial reminder job ─────────────────────────────────────────────────────────
@app.route('/api/internal/send-trial-reminders', methods=['POST'])
def send_trial_reminders():
    secret = request.headers.get('X-Internal-Secret', '')
    if secret != os.environ.get('INTERNAL_SECRET', ''):
        return jsonify({'error': 'Unauthorised'}), 401
    try:
        sent = 0
        users_3day = query(
            "SELECT email FROM ft_users WHERE subscription_status='trial' "
            "AND trial_ends_at BETWEEN NOW() + INTERVAL '2 days 20 hours' "
            "AND NOW() + INTERVAL '3 days 4 hours'"
        )
        for u in (users_3day or []):
            body = ("Hi there,\n\nYour 7-day free trial of FlexLog ends in 3 days.\n\n"
                    "To keep tracking your Amazon Flex earnings, subscribe for just £3/month.\n\n"
                    "Subscribe here: https://flexlog.co.uk/app\n\n"
                    "No contract — cancel anytime.\n\nThe FlexLog Team\nsupport@flexlog.co.uk")
            send_email(u['email'], 'Your FlexLog trial ends in 3 days', body)
            sent += 1
        users_1day = query(
            "SELECT email FROM ft_users WHERE subscription_status='trial' "
            "AND trial_ends_at BETWEEN NOW() + INTERVAL '20 hours' "
            "AND NOW() + INTERVAL '28 hours'"
        )
        for u in (users_1day or []):
            body = ("Hi there,\n\nYour FlexLog free trial ends tomorrow.\n\n"
                    "Don't lose access to your slots, mileage records and HMRC/UC reports.\n\n"
                    "Subscribe for just £3/month — less than one slot's fuel.\n\n"
                    "Subscribe here: https://flexlog.co.uk/app\n\nThe FlexLog Team\nsupport@flexlog.co.uk")
            send_email(u['email'], 'Your FlexLog trial ends tomorrow', body)
            sent += 1
        users_expired = query(
            "SELECT id, email FROM ft_users WHERE subscription_status='trial' AND trial_ends_at < NOW()"
        )
        for u in (users_expired or []):
            query("UPDATE ft_users SET subscription_status='expired' WHERE id=%s", (u['id'],), commit=True)
            body = ("Hi there,\n\nYour FlexLog free trial has ended.\n\n"
                    "Subscribe for just £3/month to continue tracking your Amazon Flex earnings "
                    "and accessing your HMRC and Universal Credit reports.\n\n"
                    "Subscribe here: https://flexlog.co.uk/app\n\nThe FlexLog Team\nsupport@flexlog.co.uk")
            send_email(u['email'], 'Your FlexLog trial has ended', body)
            sent += 1
        return jsonify({'ok': True, 'emails_sent': sent})
    except Exception as e:
        print(f'Trial reminder error: {e}')
        return jsonify({'error': str(e)}), 500

# ── User settings ─────────────────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
@token_required
def get_settings():
    user = query('SELECT hr_rate FROM ft_users WHERE id=%s', (g.user_id,), one=True)
    return jsonify({'hr_rate': float(user['hr_rate']) if user['hr_rate'] else 1.49})

@app.route('/api/settings', methods=['PUT'])
@token_required
def update_settings():
    d = request.json
    hr_rate = float(d.get('hr_rate', 1.49))
    if hr_rate < 0 or hr_rate > 10:
        return jsonify({'error': 'H&R rate must be between £0 and £10/hr'}), 400
    query('UPDATE ft_users SET hr_rate=%s WHERE id=%s', (hr_rate, g.user_id), commit=True)
    return jsonify({'ok': True, 'hr_rate': hr_rate})

# ── Stripe ────────────────────────────────────────────────────────────────────
@app.route('/api/stripe/config', methods=['GET'])
@token_required
def stripe_config():
    return jsonify({
        'publishable_key': STRIPE_PUBLISHABLE_KEY,
        'price_id': STRIPE_PRICE_ID,
        'annual_price_id': STRIPE_ANNUAL_PRICE_ID
    })

@app.route('/api/stripe/create-checkout', methods=['POST'])
@token_required
def create_checkout():
    try:
        user = query('SELECT * FROM ft_users WHERE id=%s', (g.user_id,), one=True)
        # Get or create Stripe customer
        if user['stripe_customer_id']:
            customer_id = user['stripe_customer_id']
        else:
            customer = stripe.Customer.create(email=user['email'], metadata={'user_id': g.user_id})
            customer_id = customer.id
            query('UPDATE ft_users SET stripe_customer_id=%s WHERE id=%s', (customer_id, g.user_id), commit=True)
        
        base_url = request.json.get('base_url', 'https://flexlog.co.uk')
        plan = request.json.get('plan', 'monthly')
        price_id = STRIPE_ANNUAL_PRICE_ID if plan == 'annual' else STRIPE_PRICE_ID
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=base_url + '/app?subscribed=1',
            cancel_url=base_url + '/app?cancelled=1',
            allow_promotion_codes=True,
        )
        return jsonify({'url': session.url})
    except Exception as e:
        print(f'Checkout error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            event = stripe.Event.construct_from(request.json, stripe.api_key)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')
        subscription_id = session.get('subscription')
        if customer_id:
            query('UPDATE ft_users SET subscription_status=%s, stripe_subscription_id=%s WHERE stripe_customer_id=%s',
                  ('active', subscription_id, customer_id), commit=True)
    
    elif event['type'] == 'invoice.payment_succeeded':
        sub_id = event['data']['object'].get('subscription')
        if sub_id:
            query('UPDATE ft_users SET subscription_status=%s WHERE stripe_subscription_id=%s',
                  ('active', sub_id), commit=True)
    
    elif event['type'] in ('customer.subscription.deleted', 'invoice.payment_failed'):
        sub_id = event['data']['object'].get('id') or event['data']['object'].get('subscription')
        if sub_id:
            query('UPDATE ft_users SET subscription_status=%s WHERE stripe_subscription_id=%s',
                  ('expired', sub_id), commit=True)
    
    return jsonify({'ok': True})

@app.route('/api/stripe/portal', methods=['POST'])
@token_required
def customer_portal():
    try:
        user = query('SELECT stripe_customer_id FROM ft_users WHERE id=%s', (g.user_id,), one=True)
        if not user or not user['stripe_customer_id']:
            return jsonify({'error': 'No subscription found'}), 400
        base_url = request.json.get('base_url', 'https://flexlog.co.uk')
        session = stripe.billing_portal.Session.create(
            customer=user['stripe_customer_id'],
            return_url=base_url + '/app',
        )
        return jsonify({'url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    if DATABASE_URL:
        init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1',
            host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
