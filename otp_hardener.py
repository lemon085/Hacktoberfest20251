#!/usr/bin/env python3
"""
Auto-OTP-Hardener — Attack & Defense of Time-based OTP Flows

A framework that simulates common attacks on TOTP/OTP flows and provides automated hardening rules for servers.
This includes replay attacks, window-shift misuse, and synchronization attacks.
"""

import os
import sys
import time
import json
import random
import hashlib
import hmac
import base64
import argparse
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, session
import pyotp
from collections import defaultdict, deque
import sqlite3

# Configuration
DB_NAME = "otp_hardener.db"
HARDCODED_SECRET = "JBSWY3DPEHPK3PXP"  # Base32 encoded "Hello!"
DEFAULT_WINDOW_SIZE = 1
DEFAULT_RATE_LIMIT = 5  # attempts per minute
DEFAULT_MAX_DRIFT = 30  # seconds

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    """Initialize the SQLite database with required tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            otp_code TEXT,
            success BOOLEAN,
            attack_type TEXT,
            user_agent TEXT,
            ip_address TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hardening_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            window_size INTEGER,
            rate_limit INTEGER,
            max_drift INTEGER,
            session_binding BOOLEAN,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default configuration
    cursor.execute('''
        INSERT OR IGNORE INTO hardening_configs 
        (name, window_size, rate_limit, max_drift, session_binding)
        VALUES (?, ?, ?, ?, ?)
    ''', ("default", DEFAULT_WINDOW_SIZE, DEFAULT_RATE_LIMIT, DEFAULT_MAX_DRIFT, 0))
    
    conn.commit()
    conn.close()

def get_current_config():
    """Get the current hardening configuration."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM hardening_configs WHERE name = "default"')
    config = cursor.fetchone()
    conn.close()
    
    if config:
        return {
            "window_size": config[1],
            "rate_limit": config[2],
            "max_drift": config[3],
            "session_binding": bool(config[4])
        }
    else:
        return {
            "window_size": DEFAULT_WINDOW_SIZE,
            "rate_limit": DEFAULT_RATE_LIMIT,
            "max_drift": DEFAULT_MAX_DRIFT,
            "session_binding": False
        }

def save_attempt(otp_code, success, attack_type="none"):
    """Save an OTP attempt to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO otp_attempts (timestamp, otp_code, success, attack_type, user_agent, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        time.time(),
        otp_code,
        success,
        attack_type,
        request.headers.get('User-Agent', ''),
        request.remote_addr
    ))
    
    conn.commit()
    conn.close()

def is_rate_limited():
    """Check if the current IP is rate-limited."""
    config = get_current_config()
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Get attempts in the last minute
    one_minute_ago = time.time() - 60
    cursor.execute('''
        SELECT COUNT(*) FROM otp_attempts 
        WHERE ip_address = ? AND timestamp > ?
    ''', (request.remote_addr, one_minute_ago))
    
    count = cursor.fetchone()[0]
    conn.close()
    
    return count >= config["rate_limit"]

def verify_otp(otp_code, secret=HARDCODED_SECRET):
    """Verify an OTP code against the secret."""
    config = get_current_config()
    totp = pyotp.TOTP(secret)
    
    # Check current time window
    if totp.verify(otp_code, valid_window=config["window_size"]):
        return True
    
    # If session binding is enabled, check for replay
    if config["session_binding"] and session.get('otp_verified'):
        return False  # Already used OTP in this session
    
    return False

@app.route('/')
def index():
    """Main dashboard."""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Auto-OTP-Hardener Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 1000px; margin: 0 auto; }
            .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; background-color: #f9f9f9; }
            input, button, select { padding: 8px; margin: 5px; }
            .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
            .success { background-color: #d4edda; color: #155724; }
            .error { background-color: #f8d7da; color: #721c24; }
            .warning { background-color: #fff3cd; color: #856404; }
            .config-table { width: 100%; border-collapse: collapse; }
            .config-table th, .config-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            .config-table th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Auto-OTP-Hardener Dashboard</h1>
            <p><strong>WARNING: This is a simulation tool for authorized security testing only.</strong></p>
            
            <div class="card">
                <h2>Current Configuration</h2>
                <table class="config-table">
                    <tr>
                        <th>Setting</th>
                        <th>Value</th>
                        <th>Description</th>
                    </tr>
                    <tr>
                        <td>Window Size</td>
                        <td id="windowSize">1</td>
                        <td>Number of time steps to check before/after current step</td>
                    </tr>
                    <tr>
                        <td>Rate Limit</td>
                        <td id="rateLimit">5</td>
                        <td>Max attempts per minute</td>
                    </tr>
                    <tr>
                        <td>Max Drift</td>
                        <td id="maxDrift">30</td>
                        <td>Maximum allowed time drift in seconds</td>
                    </tr>
                    <tr>
                        <td>Session Binding</td>
                        <td id="sessionBinding">Disabled</td>
                        <td>Prevent OTP reuse within same session</td>
                    </tr>
                </table>
                
                <h3>Update Configuration</h3>
                <form id="configForm">
                    <label>Window Size: <input type="number" id="newWindowSize" value="1" min="0" max="10"></label>
                    <label>Rate Limit: <input type="number" id="newRateLimit" value="5" min="1" max="100"></label>
                    <label>Max Drift (s): <input type="number" id="newMaxDrift" value="30" min="0" max="300"></label>
                    <label>Session Binding: <input type="checkbox" id="newSessionBinding"></label>
                    <button type="submit">Update Config</button>
                </form>
            </div>
            
            <div class="card">
                <h2>OTP Verification</h2>
                <form id="otpForm">
                    <input type="text" id="otpCode" placeholder="Enter OTP code" maxlength="6">
                    <button type="submit">Verify OTP</button>
                </form>
                <div id="otpStatus"></div>
            </div>
            
            <div class="card">
                <h2>Attack Simulation</h2>
                <button id="runReplayAttack">Run Replay Attack Simulation</button>
                <button id="runWindowAttack">Run Window Abuse Simulation</button>
                <button id="runRateLimitAttack">Run Rate Limit Bypass Simulation</button>
                <div id="attackStatus"></div>
            </div>
            
            <div class="card">
                <h2>Recent Attempts</h2>
                <div id="attemptsList"></div>
            </div>
            
            <div class="card">
                <h2>Hardening Recommendations</h2>
                <div id="recommendations">
                    <p>Running attack simulations will generate specific hardening recommendations here.</p>
                </div>
            </div>
        </div>
        
        <script>
            function loadConfig() {
                fetch('/api/config')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('windowSize').textContent = data.window_size;
                    document.getElementById('rateLimit').textContent = data.rate_limit;
                    document.getElementById('maxDrift').textContent = data.max_drift;
                    document.getElementById('sessionBinding').textContent = data.session_binding ? 'Enabled' : 'Disabled';
                    
                    // Update form values
                    document.getElementById('newWindowSize').value = data.window_size;
                    document.getElementById('newRateLimit').value = data.rate_limit;
                    document.getElementById('newMaxDrift').value = data.max_drift;
                    document.getElementById('newSessionBinding').checked = data.session_binding;
                });
            }
            
            function loadAttempts() {
                fetch('/api/attempts')
                .then(response => response.json())
                .then(data => {
                    const attemptsDiv = document.getElementById('attemptsList');
                    attemptsDiv.innerHTML = '<table class="config-table"><tr><th>Time</th><th>Code</th><th>Success</th><th>Attack Type</th></tr>';
                    data.attempts.forEach(attempt => {
                        const successText = attempt.success ? '✓' : '✗';
                        attemptsDiv.innerHTML += '<tr><td>' + new Date(attempt.timestamp * 1000).toLocaleString() + '</td><td>' + attempt.otp_code + '</td><td>' + successText + '</td><td>' + attempt.attack_type + '</td></tr>';
                    });
                    attemptsDiv.innerHTML += '</table>';
                });
            }
            
            document.getElementById('configForm').onsubmit = function(e) {
                e.preventDefault();
                const config = {
                    window_size: document.getElementById('newWindowSize').value,
                    rate_limit: document.getElementById('newRateLimit').value,
                    max_drift: document.getElementById('newMaxDrift').value,
                    session_binding: document.getElementById('newSessionBinding').checked
                };
                
                fetch('/api/config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadConfig();
                        document.getElementById('attackStatus').innerHTML = '<div class="status success">Configuration updated successfully</div>';
                    } else {
                        document.getElementById('attackStatus').innerHTML = '<div class="status error">Error: ' + data.error + '</div>';
                    }
                });
            };
            
            document.getElementById('otpForm').onsubmit = function(e) {
                e.preventDefault();
                const otpCode = document.getElementById('otpCode').value;
                
                fetch('/api/verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({otp: otpCode})
                })
                .then(response => response.json())
                .then(data => {
                    const statusDiv = document.getElementById('otpStatus');
                    if (data.valid) {
                        statusDiv.innerHTML = '<div class="status success">OTP verified successfully!</div>';
                    } else {
                        statusDiv.innerHTML = '<div class="status error">Invalid OTP code</div>';
                    }
                    loadAttempts();
                });
            };
            
            document.getElementById('runReplayAttack').onclick = function() {
                fetch('/api/attack/replay', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    document.getElementById('attackStatus').innerHTML = '<div class="status warning">Replay attack simulation complete. Check recommendations.</div>';
                    loadAttempts();
                    loadRecommendations();
                });
            };
            
            document.getElementById('runWindowAttack').onclick = function() {
                fetch('/api/attack/window', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    document.getElementById('attackStatus').innerHTML = '<div class="status warning">Window abuse simulation complete. Check recommendations.</div>';
                    loadAttempts();
                    loadRecommendations();
                });
            };
            
            document.getElementById('runRateLimitAttack').onclick = function() {
                fetch('/api/attack/rate_limit', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    document.getElementById('attackStatus').innerHTML = '<div class="status warning">Rate limit bypass simulation complete. Check recommendations.</div>';
                    loadAttempts();
                    loadRecommendations();
                });
            };
            
            function loadRecommendations() {
                fetch('/api/recommendations')
                .then(response => response.json())
                .then(data => {
                    const recDiv = document.getElementById('recommendations');
                    recDiv.innerHTML = '';
                    data.recommendations.forEach(rec => {
                        recDiv.innerHTML += '<p><strong>' + rec.title + ':</strong> ' + rec.description + '</p>';
                    });
                });
            }
            
            // Load initial data
            loadConfig();
            loadAttempts();
            loadRecommendations();
            
            // Refresh every 10 seconds
            setInterval(function() {
                loadAttempts();
                loadConfig();
            }, 10000);
        </script>
    </body>
    </html>
    ''')

@app.route('/api/config', methods=['GET'])
def api_get_config():
    """Get current hardening configuration."""
    config = get_current_config()
    return jsonify(config)

@app.route('/api/config', methods=['POST'])
def api_set_config():
    """Update hardening configuration."""
    try:
        data = request.json
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE hardening_configs 
            SET window_size = ?, rate_limit = ?, max_drift = ?, session_binding = ?
            WHERE name = "default"
        ''', (
            data.get('window_size', DEFAULT_WINDOW_SIZE),
            data.get('rate_limit', DEFAULT_RATE_LIMIT),
            data.get('max_drift', DEFAULT_MAX_DRIFT),
            int(data.get('session_binding', False))
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/verify', methods=['POST'])
def api_verify_otp():
    """Verify an OTP code."""
    try:
        data = request.json
        otp_code = data.get('otp')
        
        if not otp_code:
            return jsonify({"valid": False, "error": "No OTP provided"})
        
        # Check rate limit
        if is_rate_limited():
            save_attempt(otp_code, False, "rate_limit")
            return jsonify({"valid": False, "error": "Rate limit exceeded"})
        
        # Verify OTP
        is_valid = verify_otp(otp_code)
        save_attempt(otp_code, is_valid)
        
        if is_valid and get_current_config()["session_binding"]:
            session['otp_verified'] = True
        
        return jsonify({"valid": is_valid})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})

@app.route('/api/attempts')
def api_get_attempts():
    """Get recent OTP attempts."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT timestamp, otp_code, success, attack_type 
        FROM otp_attempts 
        ORDER BY timestamp DESC 
        LIMIT 20
    ''')
    
    attempts = []
    for row in cursor.fetchall():
        attempts.append({
            "timestamp": row[0],
            "otp_code": row[1],
            "success": row[2],
            "attack_type": row[3]
        })
    
    conn.close()
    return jsonify({"attempts": attempts})

@app.route('/api/attack/replay', methods=['POST'])
def api_replay_attack():
    """Simulate a replay attack."""
    # Generate a valid OTP code
    totp = pyotp.TOTP(HARDCODED_SECRET)
    current_otp = totp.now()
    
    # Try to use the same OTP multiple times (replay attack)
    results = []
    for i in range(5):
        is_valid = verify_otp(current_otp)
        save_attempt(current_otp, is_valid, "replay")
        results.append({"attempt": i+1, "code": current_otp, "success": is_valid})
        time.sleep(0.5)  # Small delay between attempts
    
    return jsonify({"success": True, "results": results})

@app.route('/api/attack/window', methods=['POST'])
def api_window_attack():
    """Simulate window abuse attack."""
    totp = pyotp.TOTP(HARDCODED_SECRET)
    
    # Get codes from adjacent time windows
    current_time = int(time.time())
    codes_to_try = []
    
    config = get_current_config()
    window_size = config["window_size"]
    
    # Try codes from current and adjacent windows
    for offset in range(-window_size-2, window_size+3):
        future_time = current_time + (offset * 30)  # TOTP period is 30s
        future_code = totp.at(future_time)
        codes_to_try.append(future_code)
    
    results = []
    for code in codes_to_try:
        is_valid = verify_otp(code)
        attack_type = "window_abuse" if not verify_otp.__code__.co_varnames else "window_abuse"
        save_attempt(code, is_valid, "window_abuse")
        results.append({"code": code, "success": is_valid})
        time.sleep(0.1)  # Small delay between attempts
    
    return jsonify({"success": True, "results": results})

@app.route('/api/attack/rate_limit', methods=['POST'])
def api_rate_limit_attack():
    """Simulate rate limit bypass attack."""
    totp = pyotp.TOTP(HARDCODED_SECRET)
    
    # Generate multiple invalid codes rapidly
    results = []
    for i in range(20):
        invalid_code = str(random.randint(100000, 999999)).zfill(6)
        is_valid = verify_otp(invalid_code)
        save_attempt(invalid_code, is_valid, "rate_limit_bypass")
        results.append({"attempt": i+1, "code": invalid_code, "success": is_valid})
    
    return jsonify({"success": True, "results": results})

@app.route('/api/recommendations')
def api_get_recommendations():
    """Generate hardening recommendations based on attack simulations."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Analyze attack patterns in the database
    cursor.execute('SELECT attack_type, COUNT(*) FROM otp_attempts WHERE attack_type != "none" GROUP BY attack_type')
    attack_counts = dict(cursor.fetchall())
    
    recommendations = []
    
    # Replay attack recommendation
    replay_count = attack_counts.get('replay', 0)
    if replay_count > 2:
        recommendations.append({
            "title": "Enable Session Binding",
            "description": f"Detected {replay_count} replay attack attempts. Enable session binding to prevent OTP reuse within the same session."
        })
    
    # Window abuse recommendation
    window_count = attack_counts.get('window_abuse', 0)
    if window_count > 5:
        recommendations.append({
            "title": "Reduce Time Window",
            "description": f"Detected potential window abuse with {window_count} suspicious attempts. Reduce the time window size to minimize attack surface."
        })
    
    # Rate limit recommendation
    rate_limit_count = attack_counts.get('rate_limit_bypass', 0)
    if rate_limit_count > 5:
        recommendations.append({
            "title": "Implement Stricter Rate Limiting",
            "description": f"Detected {rate_limit_count} rate limit bypass attempts. Implement stricter rate limiting or account lockout policies."
        })
    
    # Default recommendations
    if not recommendations:
        recommendations = [
            {
                "title": "Review Current Configuration",
                "description": "Current configuration appears secure, but consider reviewing time window size and rate limits."
            },
            {
                "title": "Enable Session Binding",
                "description": "Enable session binding to prevent OTP replay attacks."
            },
            {
                "title": "Monitor for Brute Force",
                "description": "Implement monitoring for repeated invalid OTP attempts."
            }
        ]
    
    conn.close()
    return jsonify({"recommendations": recommendations})

def run_attack_simulations():
    """Run all attack simulations and generate a report."""
    print("Running attack simulations...")
    
    # Simulate different attack types
    print("  - Simulating replay attacks...")
    for _ in range(3):
        api_replay_attack()
    
    print("  - Simulating window abuse...")
    for _ in range(2):
        api_window_attack()
    
    print("  - Simulating rate limit bypass...")
    api_rate_limit_attack()
    
    print("Attack simulations complete!")
    
    # Generate report
    with open("otp_hardener_report.json", "w") as f:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Get attack statistics
        cursor.execute('SELECT attack_type, COUNT(*) FROM otp_attempts WHERE attack_type != "none" GROUP BY attack_type')
        attack_stats = dict(cursor.fetchall())
        
        # Get configuration
        config = get_current_config()
        
        # Get recommendations
        rec_response = api_get_recommendations()
        recommendations = rec_response.get_json()["recommendations"]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "configuration": config,
            "attack_statistics": attack_stats,
            "recommendations": recommendations
        }
        
        json.dump(report, f, indent=2)
        conn.close()
    
    print("Report saved as otp_hardener_report.json")

def main():
    parser = argparse.ArgumentParser(description='Auto-OTP-Hardener — Attack & Defense of Time-based OTP Flows')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--run-attacks', action='store_true', help='Run attack simulations and generate report')
    args = parser.parse_args()
    
    # Initialize database
    init_db()
    
    if args.run_attacks:
        run_attack_simulations()
        print("\nHardening recommendations:")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM otp_attempts WHERE attack_type != "none" LIMIT 5')
        recent_attacks = cursor.fetchall()
        conn.close()
        
        if recent_attacks:
            print("  - Review recent attack attempts in the database")
            print("  - Adjust time window size based on drift tolerance needs")
            print("  - Implement account lockout after multiple failed attempts")
            print("  - Consider using higher entropy secrets")
        else:
            print("  - No attack attempts detected in simulation")
            print("  - Consider running with --run-attacks flag for testing")
        return
    
    print(f"Starting Auto-OTP-Hardener on port {args.port}...")
    print("Access the dashboard at: http://localhost:{}".format(args.port))
    print("WARNING: This is a simulation tool for authorized security testing only.")
    
    app.run(host='0.0.0.0', port=args.port, debug=False)

if __name__ == '__main__':
    main()
