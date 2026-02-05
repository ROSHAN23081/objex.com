/**
 * Session Data Model - Secure storage for demo captures
 * Implements encryption at rest and automatic cleanup
 */

const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const DB_PATH = path.join(__dirname, '../../data/demo-sessions.db');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);

class SessionData {
  constructor() {
    this.db = new sqlite3.Database(DB_PATH);
    this.init();
  }

  init() {
    // Sessions table with automatic expiration
    this.db.run(`
      CREATE TABLE IF NOT EXISTS capture_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        mo_username TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        status TEXT DEFAULT 'active'
      )
    `);

    // Encrypted phone/safety code storage
    this.db.run(`
      CREATE TABLE IF NOT EXISTS captured_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        encrypted_phone TEXT NOT NULL,
        encrypted_safety_code TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'new',
        FOREIGN KEY (session_id) REFERENCES capture_sessions(session_id)
      )
    `);

    // Message audit log
    this.db.run(`
      CREATE TABLE IF NOT EXISTS message_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        mo_username TEXT NOT NULL,
        encrypted_phone TEXT NOT NULL,
        message_preview TEXT,
        sent_at DATETIME,
        status TEXT,
        delivery_status TEXT,
        FOREIGN KEY (session_id) REFERENCES capture_sessions(session_id)
      )
    `);

    // Auto-cleanup expired sessions
    setInterval(() => this.cleanupExpired(), 5 * 60 * 1000); // Every 5 minutes
  }

  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  decrypt(encryptedData) {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  async createSession(sessionId, moUsername) {
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO capture_sessions (session_id, mo_username, expires_at) 
         VALUES (?, ?, ?)`,
        [sessionId, moUsername, expiresAt.toISOString()],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, sessionId, expiresAt });
        }
      );
    });
  }

  async captureData(sessionId, phoneNumber, safetyCode) {
    const encryptedPhone = this.encrypt(phoneNumber);
    const encryptedCode = this.encrypt(safetyCode);
    
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO captured_data (session_id, encrypted_phone, encrypted_safety_code) 
         VALUES (?, ?, ?)`,
        [sessionId, encryptedPhone, encryptedCode],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, status: 'captured' });
        }
      );
    });
  }

  async getSessionData(sessionId, moUsername) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT cd.* FROM captured_data cd
         JOIN capture_sessions cs ON cd.session_id = cs.session_id
         WHERE cd.session_id = ? AND cs.mo_username = ? AND cd.status = 'new'
         AND cs.expires_at > datetime('now')`,
        [sessionId, moUsername],
        (err, rows) => {
          if (err) {
            reject(err);
            return;
          }
          
          // Decrypt for authorized access only
          const decrypted = rows.map(row => ({
            id: row.id,
            phoneNumber: this.decrypt(row.encrypted_phone),
            safetyCode: this.decrypt(row.encrypted_safety_code),
            createdAt: row.created_at
          }));
          resolve(decrypted);
        }
      );
    });
  }

  async markAsSent(sessionId, phoneNumber) {
    const encryptedPhone = this.encrypt(phoneNumber);
    
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE captured_data SET status = 'sent' 
         WHERE session_id = ? AND encrypted_phone = ?`,
        [sessionId, encryptedPhone],
        function(err) {
          if (err) reject(err);
          else resolve({ updated: this.changes });
        }
      );
    });
  }

  async logMessage(sessionId, moUsername, phoneNumber, message, status) {
    const encryptedPhone = this.encrypt(phoneNumber);
    const preview = message.substring(0, 50) + (message.length > 50 ? '...' : '');
    
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO message_logs 
         (session_id, mo_username, encrypted_phone, message_preview, sent_at, status) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [sessionId, moUsername, encryptedPhone, preview, new Date().toISOString(), status],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID });
        }
      );
    });
  }

  async cleanupExpired() {
    this.db.run(
      `DELETE FROM captured_data WHERE session_id IN 
       (SELECT session_id FROM capture_sessions WHERE expires_at < datetime('now'))`
    );
    this.db.run(
      `DELETE FROM capture_sessions WHERE expires_at < datetime('now')`
    );
  }

  async endSession(sessionId) {
    return new Promise((resolve, reject) => {
      // Immediate purge of session data
      this.db.run(
        `DELETE FROM captured_data WHERE session_id = ?`,
        [sessionId],
        (err) => {
          if (err) reject(err);
          else {
            this.db.run(
              `DELETE FROM capture_sessions WHERE session_id = ?`,
              [sessionId],
              (err) => {
                if (err) reject(err);
                else resolve({ purged: true });
              }
            );
          }
        }
      );
    });
  }
}

module.exports = new SessionData();
