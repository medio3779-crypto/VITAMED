const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = 'vitamed_session';
const SESSION_DAYS = 7;

if (!process.env.DATABASE_URL) {
  console.error('ERROR: Set DATABASE_URL in the hosting environment.');
  process.exit(1);
}
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('ERROR: Set JWT_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name VARCHAR(70) NOT NULL,
      email VARCHAR(190) NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (LOWER(email));
  `);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'محاولات كتير في وقت قصير. حاول تاني بعد شوية.' }
});

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, createdAt: row.created_at };
}

function issueSession(res, user) {
  const token = jwt.sign(
    { sub: String(user.id), email: user.email },
    JWT_SECRET,
    { expiresIn: `${SESSION_DAYS}d`, issuer: 'vitamed' }
  );
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000
  });
}

async function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ message: 'سجّل الدخول الأول.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'vitamed' });
    const result = await pool.query(
      'SELECT id, name, email, created_at FROM users WHERE id = $1',
      [payload.sub]
    );
    if (!result.rows[0]) return res.status(401).json({ message: 'الجلسة غير صالحة. سجّل الدخول من جديد.' });
    req.user = result.rows[0];
    next();
  } catch {
    return res.status(401).json({ message: 'انتهت الجلسة. سجّل الدخول من جديد.' });
  }
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok', app: 'VITAMED API' }));

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || name.length > 70) return res.status(400).json({ message: 'الاسم لازم يكون من حرفين إلى 70 حرف.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 190) return res.status(400).json({ message: 'اكتب بريد إلكتروني صحيح.' });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ message: 'كلمة المرور لازم تكون 8 أحرف على الأقل.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
      [name, email, passwordHash]
    );
    const user = result.rows[0];
    issueSession(res, user);
    return res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error && error.code === '23505') return res.status(409).json({ message: 'البريد ده مسجل بالفعل. جرّب تسجيل الدخول.' });
    next(error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [email]);
    const row = result.rows[0];
    const valid = row ? await bcrypt.compare(password, row.password_hash) : false;
    if (!valid) return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
    issueSession(res, row);
    return res.json({ user: publicUser(row) });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'lax', path: '/' });
  res.json({ message: 'تم تسجيل الخروج.' });
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: IS_PRODUCTION ? '1h' : 0 }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ message: 'حصل خطأ في السيرفر. حاول تاني.' });
});

initializeDatabase().then(() => {
  app.listen(PORT, () => console.log(`VITAMED is running on port ${PORT}`));
}).catch((error) => {
  console.error('Database initialization failed:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
