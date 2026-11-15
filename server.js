const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const { db, reset, verifyPassword } = require('./db');

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

// CSRF token po sesiji, stvara se pri prvom zahtjevu.
// Mora biti nakon session middlewarea, inace req.session ne postoji.
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Zajednicki podaci za glavnu stranicu (obje sekcije).
function renderIndex(req, res, sqli = { vuln: true, username: '' }) {
  const user = req.session.userId
    ? db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(req.session.userId)
    : null;
  const flash = req.session.flash;
  delete req.session.flash;

  res.render('index', {
    sqli,
    user,
    flash,
    csrfToken: req.session.csrfToken,
    csrfVuln: req.session.csrfVuln ?? true,
    csrfLog: req.session.csrfLog ?? [],
  });
}

// Vraca opis problema s CSRF tokenom ili null ako je token ispravan.
function csrfProblem(req) {
  const token = req.body._csrf;
  if (typeof token !== 'string' || token === '') return 'token nedostaje';
  if (token !== req.session.csrfToken) return 'token neispravan';
  return null;
}

app.get('/', (req, res) => {
  renderIndex(req, res);
});

// ---------- SQL Injection ----------
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

  renderIndex(req, res, sqli);
});

// ---------- Prijava ----------
app.post('/login', (req, res) => {
  const username = String(req.body.username ?? '');
  const password = String(req.body.password ?? '');
  const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(username);

  if (user && verifyPassword(password, user.password_hash)) {
    req.session.userId = user.id;
  } else {
    req.session.flash = 'Neispravno korisničko ime ili lozinka.';
  }
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ---------- CSRF ----------
// Prekidac se cuva u sesiji jer krivotvoreni zahtjev s napadacke stranice
// ne nosi checkbox. Sama promjena prekidaca UVIJEK trazi ispravan token,
// inace bi napadac mogao prvo ukljuciti ranjivost pa onda napasti.
app.post('/csrf/toggle', (req, res) => {
  const problem = csrfProblem(req);
  if (problem) {
    req.session.flash = `Postavka nije spremljena: ${problem}.`;
  } else {
    req.session.csrfVuln = req.body.vuln !== undefined;
  }
  res.redirect('/');
});

app.post('/csrf/email', (req, res) => {
  const email = String(req.body.email ?? '').trim();
  const vuln = req.session.csrfVuln ?? true;
  const problem = csrfProblem(req);
  let outcome;

  if (!req.session.userId) {
    outcome = 'ODBIJENO – niste prijavljeni';
  } else if (!vuln && problem) {
    // SIGURNO: bez ispravnog tokena zahtjev se odbija.
    outcome = `ODBIJENO – ${problem}`;
  } else if (!email) {
    outcome = 'ODBIJENO – prazan e-mail';
  } else {
    // RANJIVO (vuln): token se uopce ne provjerava.
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, req.session.userId);
    outcome = vuln ? 'IZVRŠENO (ranjivost uključena, token se ne provjerava)' : 'IZVRŠENO (token ispravan)';
  }

  const entry = {
    time: new Date().toLocaleTimeString('hr-HR', { timeZone: 'Europe/Zagreb' }),
    email,
    referer: req.get('Referer') || '-',
    outcome,
  };
  req.session.csrfLog = [entry, ...(req.session.csrfLog ?? [])].slice(0, 10);
  res.redirect('/');
});

// Simulacija zlonamjerne stranice (u stvarnosti bi bila na drugoj domeni).
app.get('/napadac', (req, res) => {
  res.render('napadac');
});

// ---------- Reset ----------
app.post('/reset', (req, res) => {
  reset();
  res.redirect('/');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server radi na http://localhost:${port}`);
});
