const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));

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
  res.render('index');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server radi na http://localhost:${port}`);
});
