const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const { db, reset } = require('./db');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
// Express 5 ostavlja req.body undefined ako zahtjev nema tijelo forme.
app.use((req, res, next) => {
  req.body ??= {};
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'lokalni-dev-secret',
  resave: false,
  saveUninitialized: true,
}));

// CSRF token po sesiji, stvara se pri prvom zahtjevu (koristi se u Fazi 4).
// Mora biti nakon session middlewarea, inace req.session ne postoji.
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

app.get('/', (req, res) => {
  res.render('index', { sqli: { vuln: true, username: '' } });
});

// SQL Injection: pretraga korisnika po korisnickom imenu.
// Prekidac je checkbox u formi; neoznaceni checkbox preglednik uopce ne salje.
app.post('/sqli', (req, res) => {
  const vuln = req.body.vuln !== undefined;
  const username = String(req.body.username ?? '');
  const sqli = { vuln, username, query: '', params: null, rows: [], error: null };

  try {
    if (vuln) {
      // RANJIVO: unos se lijepi direktno u SQL string.
      sqli.query = `SELECT id, username, email FROM users WHERE username = '${username}'`;
      sqli.rows = db.prepare(sqli.query).all();
    } else {
      // SIGURNO: parametrizirani upit, unos se veze kao vrijednost.
      sqli.query = 'SELECT id, username, email FROM users WHERE username = ?';
      sqli.params = [username];
      sqli.rows = db.prepare(sqli.query).all(username);
    }
  } catch (err) {
    sqli.error = err.message;
  }

  res.render('index', { sqli });
});

app.post('/reset', (req, res) => {
  reset();
  res.redirect('/');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server radi na http://localhost:${port}`);
});
