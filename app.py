from flask import Flask, render_template, request, redirect, jsonify, session
import sqlite3
import smtplib
import secrets
import os
import random
import socket
from email.message import EmailMessage
from datetime import datetime, timedelta
print("APP.PY STARTED")

app = Flask(__name__)
app.secret_key = 'animal-detection-secret-key-2024'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')


# Email configuration
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

def get_local_ip():
    """Get the local IP address dynamically"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def init_database():
    """Initialize the database with proper schema migration"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if the table exists and get its structure
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        # Check if otp_code column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'otp_code' not in columns:
            print("🔄 Updating database schema...")
            # Create a new table with the updated schema
            cursor.execute('''
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    otp_code TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    otp_expires_at TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Copy data from old table if it exists
            try:
                cursor.execute('INSERT INTO users_new (id, email, is_verified, created_at) SELECT id, email, is_verified, created_at FROM users')
            except:
                print("ℹ️ No existing data to migrate")
            
            # Drop old table and rename new one
            cursor.execute('DROP TABLE users')
            cursor.execute('ALTER TABLE users_new RENAME TO users')
            print("✅ Database schema updated successfully!")
        else:
            print("✅ Database schema is up to date")
    else:
        # Create new table with complete schema
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                otp_code TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                otp_expires_at TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        print("✅ New database created with OTP support")
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp_code):
    """Send OTP email to user with multiple fallback methods"""
    try:
        msg = EmailMessage()
        msg['Subject'] = "Your Animal Detection Verification Code"
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        msg.set_content(f"""
🐾 Animal Detection Alerts - OTP Verification

Your verification code is:
{otp_code}

Enter this code on the website to complete your registration.

This code will expire in 10 minutes.

You will receive email alerts whenever our system detects animals.

Thank you!
Animal Detection System
        """)
        
        # Try multiple SMTP methods
        methods = [
            ('smtp.gmail.com', 465, True),  # SSL
            ('smtp.gmail.com', 587, False)  # TLS
        ]
        
        for host, port, use_ssl in methods:
            try:
                if use_ssl:
                    with smtplib.SMTP_SSL(host, port) as smtp:
                        smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
                        smtp.send_message(msg)
                else:
                    with smtplib.SMTP(host, port) as smtp:
                        smtp.starttls()
                        smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
                        smtp.send_message(msg)
                
                print(f"✅ OTP sent to: {email}")
                return True
            except Exception as e:
                print(f"⚠️ SMTP method failed ({host}:{port}): {e}")
                continue
        
        print(f"❌ All SMTP methods failed for: {email}")
        return False
        
    except Exception as e:
        print(f"❌ Error sending OTP: {e}")
        return False

def log_scan(email, ip_address, user_agent, status="registration_attempt"):
    """Log QR code scans and registration attempts"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"🎯 QR CODE SCANNED - {timestamp}")
    print(f"   📧 Email: {email}")
    print(f"   🌐 IP: {ip_address}")
    print(f"   📱 Device: {user_agent[:80]}...")
    print(f"   📊 Status: {status}")
    print("-" * 60)

@app.route('/')
def index():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Log the scan
        log_scan(email, ip_address, user_agent, "registration_attempt")
        
        try:
            conn = get_db_connection()
            
            # Check if email already verified
            existing_user = conn.execute(
                'SELECT * FROM users WHERE email = ? AND is_verified = 1', 
                (email,)
            ).fetchone()
            
            if existing_user:
                conn.close()
                log_scan(email, ip_address, user_agent, "already_verified")
                return '''
                <div style="text-align:center; padding:20px; font-family: Arial;">
                    <h2 style="color:green;">✅ Already Registered!</h2>
                    <p>This email is already receiving animal alerts.</p>
                    <a href="/" style="color:blue;">Back to Home</a>
                </div>
                '''
            
            # Delete any previous unverified entries
            conn.execute('DELETE FROM users WHERE email = ? AND is_verified = 0', (email,))
            
            # Insert new user with OTP and client info
            conn.execute(
                'INSERT INTO users (email, otp_code, is_verified, otp_expires_at, ip_address, user_agent) VALUES (?, ?, 0, ?, ?, ?)',
                (email, otp_code, expires_at, ip_address, user_agent)
            )
            conn.commit()
            conn.close()
            
            # Send OTP email
            if send_otp_email(email, otp_code):
                session['verify_email'] = email
                log_scan(email, ip_address, user_agent, "otp_sent")
                return redirect('/verify_otp')
            else:
                log_scan(email, ip_address, user_agent, "email_failed")
                return '''
                <div style="text-align:center; padding:20px;">
                    <h2 style="color:red;">❌ Email Error</h2>
                    <p>Failed to send OTP. Please try again later or contact support.</p>
                    <a href="/" style="color:blue;">Back to Registration</a>
                </div>
                '''
                
        except sqlite3.IntegrityError:
            log_scan(email, ip_address, user_agent, "database_error")
            return '''
            <div style="text-align:center; padding:20px;">
                <h2 style="color:red;">❌ Database Error</h2>
                <p>Please try again in a moment.</p>
                <a href="/" style="color:blue;">Back to Registration</a>
            </div>
            '''
        except Exception as e:
            log_scan(email, ip_address, user_agent, f"error: {str(e)}")
            return f'''
            <div style="text-align:center; padding:20px;">
                <h2 style="color:red;">❌ System Error</h2>
                <p>An unexpected error occurred: {str(e)}</p>
                <p>Please try refreshing the page or contact support.</p>
                <a href="/" style="color:blue;">Back to Registration</a>
            </div>
            '''
    
    # Log page access (GET request)
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_scan("Page Accessed", ip_address, user_agent, "qr_scan_page_load")
    
    local_ip = get_local_ip()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Animal Detection - Register</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .container {{ 
                background: white;
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                max-width: 400px;
                width: 100%;
                text-align: center;
            }}
            .logo {{
                font-size: 3em;
                margin-bottom: 10px;
            }}
            h2 {{
                color: #333;
                margin-bottom: 10px;
            }}
            p {{
                color: #666;
                margin-bottom: 20px;
                line-height: 1.5;
            }}
            input[type="email"] {{ 
                width: 100%; 
                padding: 15px; 
                margin: 15px 0; 
                border: 2px solid #ddd;
                border-radius: 8px;
                font-size: 16px;
                box-sizing: border-box;
            }}
            button {{ 
                background: #007cba; 
                color: white; 
                padding: 15px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer;
                font-size: 18px;
                width: 100%;
                font-weight: bold;
                transition: background 0.3s;
            }}
            button:hover {{
                background: #005a87;
            }}
            .info-box {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                margin-top: 20px;
                font-size: 14px;
                color: #666;
            }}
            .network-info {{
                background: #e7f3ff;
                padding: 10px;
                border-radius: 5px;
                margin: 10px 0;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🐾</div>
            <h2>Animal Detection Alerts</h2>
            <p>Enter your email to receive OTP verification and get alerts when animals are detected!</p>
            
            <div class="network-info">
                <strong>Network Access:</strong><br>
                Use this URL for QR code: http://{local_ip}:5000
            </div>
            
            <form method="POST">
                <input type="email" name="email" placeholder="Enter your email address" required>
                <button type="submit">Send OTP</button>
            </form>
            
            <div class="info-box">
                <strong>How it works:</strong><br>
                1. Enter email & receive OTP<br>
                2. Verify with OTP code<br>
                3. Get animal detection alerts!
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('verify_email')
    if not email:
        return redirect('/')
    
    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        ip_address = request.remote_addr
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND otp_code = ? AND otp_expires_at > datetime("now")',
            (email, entered_otp)
        ).fetchone()
        
        if user:
            conn.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            session.pop('verify_email', None)
            
            log_scan(email, ip_address, "OTP Verification", "verified_success")
            print(f"🎉 NEW USER VERIFIED: {email}")
            
            return '''
            <div style="text-align:center; padding:20px; font-family: Arial;">
                <h2 style="color:green;">✅ Verified Successfully!</h2>
                <p>Your email has been verified successfully!</p>
                <p>You will now receive animal detection alerts.</p>
                <p>You can close this window.</p>
            </div>
            '''
        else:
            conn.close()
            log_scan(email, ip_address, "OTP Verification", "otp_failed")
            return '''
            <div style="text-align:center; padding:20px; font-family: Arial;">
                <h2 style="color:red;">❌ Invalid OTP</h2>
                <p>The OTP is invalid or has expired.</p>
                <p>Please try again.</p>
                <a href="/verify_otp" style="color:blue;">Try Again</a>
            </div>
            '''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Verify OTP</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .container {{ 
                background: white;
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                max-width: 400px;
                width: 100%;
                text-align: center;
            }}
            input[type="text"] {{ 
                width: 100%; 
                padding: 15px; 
                margin: 15px 0; 
                border: 2px solid #ddd;
                border-radius: 8px;
                font-size: 18px;
                text-align: center;
                letter-spacing: 5px;
                box-sizing: border-box;
            }}
            button {{ 
                background: #007cba; 
                color: white; 
                padding: 15px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer;
                font-size: 18px;
                width: 100%;
                font-weight: bold;
            }}
            .email-display {{
                background: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
                margin: 10px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 Enter OTP Code</h2>
            <p>We sent a 6-digit verification code to:</p>
            <div class="email-display">
                <strong>{email}</strong>
            </div>
            <form method="POST">
                <input type="text" name="otp" placeholder="Enter 6-digit OTP" maxlength="6" required pattern="[0-9]{{6}}">
                <button type="submit">Verify & Register</button>
            </form>
            <p style="margin-top: 20px;"><a href="/" style="color:blue;">Back to Registration</a></p>
        </div>
    </body>
    </html>
    '''

@app.route('/api/verified_emails')
def get_verified_emails():
    """API endpoint for predict.py to get verified emails"""
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT email FROM users WHERE is_verified = 1').fetchall()
        conn.close()
        emails = [user['email'] for user in users]
        print(f"📧 API: Sending {len(emails)} verified emails to detection system")
        return jsonify(emails)
    except Exception as e:
        print(f"❌ API Error: {e}")
        return jsonify([])

@app.route('/admin')
def admin_dashboard():
    """Real-time admin dashboard to monitor QR scans"""
    conn = get_db_connection()
    
    # Get stats
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    verified_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_verified = 1').fetchone()[0]
    recent_scans = conn.execute(
        'SELECT email, ip_address, user_agent, created_at, is_verified FROM users ORDER BY created_at DESC LIMIT 20'
    ).fetchall()
    
    conn.close()
    
    local_ip = get_local_ip()
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard - Animal Detection</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .dashboard {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .stats {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
            .stat-card {{ background: #007cba; color: white; padding: 20px; border-radius: 8px; text-align: center; flex: 1; min-width: 150px; }}
            .stat-card h3 {{ margin: 0; font-size: 14px; }}
            .stat-card div {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
            .verified {{ color: green; font-weight: bold; }}
            .pending {{ color: orange; font-weight: bold; }}
            .device-info {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
            .refresh-btn {{ background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 10px 0; }}
            .network-info {{ background: #e7f3ff; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        </style>
        <script>
            function refreshData() {{
                fetch('/admin/data')
                    .then(response => response.json())
                    .then(data => {{
                        document.getElementById('totalUsers').textContent = data.total_users;
                        document.getElementById('verifiedUsers').textContent = data.verified_users;
                        document.getElementById('pendingUsers').textContent = data.pending_users;
                        document.getElementById('scansTable').innerHTML = data.scans_html;
                    }});
            }}
            
            // Auto-refresh every 15 seconds
            setInterval(refreshData, 15000);
        </script>
    </head>
    <body>
        <div class="dashboard">
            <h1>🐾 Animal Detection - Admin Dashboard</h1>
            <p>Real-time monitoring of QR code scans and registrations</p>
            
            <div class="network-info">
                <strong>QR Code URL:</strong> http://{local_ip}:5000<br>
                <strong>Local Access:</strong> http://localhost:5000
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Total Scans</h3>
                    <div id="totalUsers">{total_users}</div>
                </div>
                <div class="stat-card">
                    <h3>Verified Users</h3>
                    <div id="verifiedUsers">{verified_users}</div>
                </div>
                <div class="stat-card">
                    <h3>Pending Verification</h3>
                    <div id="pendingUsers">{total_users - verified_users}</div>
                </div>
            </div>
            
            <button class="refresh-btn" onclick="refreshData()">🔄 Refresh Now</button>
            <p><small>Auto-refreshes every 15 seconds</small></p>
        </div>
        
        <div class="dashboard">
            <h2>Recent QR Code Scans & Registrations</h2>
            <div id="scansTable">
    '''
    
    for scan in recent_scans:
        status = "✅ Verified" if scan['is_verified'] else "⏳ Pending OTP"
        status_class = "verified" if scan['is_verified'] else "pending"
        html += f'''
                <tr>
                    <td>{scan['email']}</td>
                    <td>{scan['ip_address']}</td>
                    <td class="device-info" title="{scan['user_agent']}">{scan['user_agent'][:50]}...</td>
                    <td>{scan['created_at']}</td>
                    <td class="{status_class}">{status}</td>
                </tr>
        '''
    
    html += '''
            </table>
            
            <h3>📊 Quick Links</h3>
            <ul>
                <li><a href="/admin/emails">View All Emails (Manage)</a></li>
                <li><a href="/">Registration Page</a></li>
                <li><a href="/stats">Public Stats</a></li>
            </ul>
        </div>
    </body>
    </html>
    '''
    return html

@app.route('/admin/data')
def admin_data():
    """API endpoint for real-time admin data"""
    conn = get_db_connection()
    
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    verified_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_verified = 1').fetchone()[0]
    recent_scans = conn.execute(
        'SELECT email, ip_address, user_agent, created_at, is_verified FROM users ORDER BY created_at DESC LIMIT 20'
    ).fetchall()
    
    conn.close()
    
    # Generate HTML for scans table
    scans_html = '<table><tr><th>Email</th><th>IP Address</th><th>Device Info</th><th>Time</th><th>Status</th></tr>'
    for scan in recent_scans:
        status = "✅ Verified" if scan['is_verified'] else "⏳ Pending OTP"
        status_class = "verified" if scan['is_verified'] else "pending"
        scans_html += f'''
            <tr>
                <td>{scan['email']}</td>
                <td>{scan['ip_address']}</td>
                <td class="device-info" title="{scan['user_agent']}">{scan['user_agent'][:50]}...</td>
                <td>{scan['created_at']}</td>
                <td class="{status_class}">{status}</td>
            </tr>
        '''
    scans_html += '</table>'
    
    return jsonify({
        'total_users': total_users,
        'verified_users': verified_users,
        'pending_users': total_users - verified_users,
        'scans_html': scans_html
    })

@app.route('/admin/emails')
def admin_emails():
    """Admin page to view and manage registered emails"""
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    
    html = '''
    <html>
    <head>
        <title>Admin - Manage Emails</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #f5f5f5; }
            .delete-btn { color: red; text-decoration: none; }
        </style>
    </head>
    <body>
        <h2>📧 Manage Registered Emails</h2>
        <p><a href="/admin">← Back to Dashboard</a></p>
        <table>
            <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Verified</th>
                <th>IP Address</th>
                <th>Registered</th>
                <th>Action</th>
            </tr>
    '''
    
    for user in users:
        html += f'''
            <tr>
                <td>{user['id']}</td>
                <td>{user['email']}</td>
                <td>{"✅" if user['is_verified'] else "❌"}</td>
                <td>{user['ip_address']}</td>
                <td>{user['created_at']}</td>
                <td><a href="/admin/delete/{user['id']}" class="delete-btn" onclick="return confirm('Delete {user['email']}?')">🗑️ Delete</a></td>
            </tr>
        '''
    
    html += '''
        </table>
    </body>
    </html>
    '''
    return html

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    """Delete a user by ID"""
    conn = get_db_connection()
    user = conn.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        print(f"🗑️ Admin deleted user: {user['email']}")
    conn.close()
    return redirect('/admin/emails')

@app.route('/stats')
def stats():
    """Public statistics page"""
    conn = get_db_connection()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    verified_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_verified = 1').fetchone()[0]
    conn.close()
    
    return f'''
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center;">
        <h2>📊 Animal Detection System Stats</h2>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <p><strong>Total Registrations:</strong> {total_users}</p>
            <p><strong>Verified Users:</strong> {verified_users}</p>
            <p><strong>Pending Verifications:</strong> {total_users - verified_users}</p>
        </div>
        <a href="/">Back to Registration</a>
    </div>
    '''

if __name__ == "__main__":
    local_ip = get_local_ip()

    print("🐾 Animal Detection System with OTP Verification")
    print("📍 Local access: http://localhost:5000")
    print(f"📍 Network access: http://{local_ip}:5000")
    print("📊 Admin dashboard: http://localhost:5000/admin")
    print("📧 OTP emails will be sent for verification")
    print("=" * 60)
    print("🎯 REAL-TIME SCAN MONITORING ACTIVATED!")
    print("   Every QR code scan will be logged here")
    print("   Check /admin for live dashboard")
    print("=" * 60)
    print(f"\n📱 QR CODE GENERATION:")
    print(f"   Use this URL for QR code: http://{local_ip}:5000")
    print("=" * 60)

    app.run(debug=True)


