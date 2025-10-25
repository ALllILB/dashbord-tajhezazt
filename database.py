import sqlite3
import bcrypt
from contextlib import contextmanager

@contextmanager
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Create Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'visitor'))
            )
        ''')
        
        # Create Systems table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS systems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                location TEXT NOT NULL,
                system_name TEXT NOT NULL,
                user TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                antivirus_status TEXT NOT NULL CHECK (antivirus_status IN ('فعال', 'غیرفعال')),
                firewall_status TEXT NOT NULL CHECK (firewall_status IN ('فعال', 'غیرفعال'))
            )
        ''')
        
        # Create Telephony table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telephony (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                location TEXT NOT NULL,
                personnel_name TEXT NOT NULL,
                internal_number TEXT NOT NULL,
                phone_type TEXT NOT NULL,
                upgrade_needed TEXT NOT NULL CHECK (upgrade_needed IN ('بله', 'خیر'))
            )
        ''')
        
        # Create CCTV table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cctv (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                location TEXT NOT NULL,
                point_needed TEXT NOT NULL,
                priority TEXT NOT NULL CHECK (priority IN ('فوری', 'عادی')),
                reason TEXT
            )
        ''')
        
        # Create Infrastructure table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS infrastructure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                location TEXT NOT NULL,
                printer INTEGER DEFAULT 0,
                computer INTEGER DEFAULT 0,
                voip_phone INTEGER DEFAULT 0,
                camera INTEGER DEFAULT 0,
                attendance_clock INTEGER DEFAULT 0,
                nutrition_clock INTEGER DEFAULT 0,
                nvr INTEGER DEFAULT 0,
                managed_switch INTEGER DEFAULT 0,
                unmanaged_switch INTEGER DEFAULT 0,
                server INTEGER DEFAULT 0,
                voip_pbx INTEGER DEFAULT 0,
                firewall INTEGER DEFAULT 0
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                         ('admin', hashed_password.decode('utf-8'), 'admin'))
        
        conn.commit()

def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False