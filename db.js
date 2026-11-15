const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// Baza u memoriji: puni se pri svakom pokretanju i resetira gumbom.
const db = new DatabaseSync(':memory:');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 32);
  return crypto.timingSafeEqual(candidate, Buffer.from(hash, 'hex'));
}

const SEED_USERS = [
  { username: 'admin', email: 'admin@lab2.example', password: 'Admin-Lab2-2026' },
  { username: 'ana', email: 'ana@lab2.example', password: 'ana123' },
  { username: 'ivan', email: 'ivan@lab2.example', password: 'ivan123' },
];

function reset() {
  db.exec(`
    DROP TABLE IF EXISTS users;
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);
  const insert = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
  for (const u of SEED_USERS) {
    insert.run(u.username, u.email, hashPassword(u.password));
  }
}

reset();

module.exports = { db, reset, verifyPassword };
