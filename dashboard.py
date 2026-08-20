from flask import Flask, render_template
import mysql.connector
import os

# Force Flask to look for HTML files in the exact same folder as dashboard.py
app = Flask(__name__, template_folder=os.path.dirname(__file__))

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'inventory_db'
}

@app.route('/')
def dashboard():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM authorized_devices ORDER BY last_seen DESC")
        devices = cursor.fetchall()
        conn.close()
    except Exception as e:
        devices = []
        return render_template('dashboard.html', devices=devices, error=str(e))

    return render_template('dashboard.html', devices=devices)

@app.route('/cves')
def cves_dashboard():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM device_cve_history 
            ORDER BY detected_at DESC
        """)
        cves = cursor.fetchall()
        conn.close()
    except Exception as e:
        cves = []
        return render_template('cves.html', cves=cves, error=str(e))

    return render_template('cves.html', cves=cves)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)