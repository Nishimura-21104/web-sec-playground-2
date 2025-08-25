import express from 'express';
import next from 'next';
import session from 'express-session';
import connectSessionKnex from 'connect-session-knex';
import knex from 'knex';
import bcrypt from 'bcryptjs';

const KnexSessionStore = connectSessionKnex(session);

const port = 3000;
const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();

// Knex setup for SQLite
const db = knex({
  client: 'sqlite3',
  connection: {
    filename: './database.sqlite',
  },
  useNullAsDefault: true,
});

// テーブル作成処理をまとめて同期的に実行
async function setupTables() {
  // usersテーブル
  const usersExists = await db.schema.hasTable('users');
  if (!usersExists) {
    await db.schema.createTable('users', (table) => {
      table.increments('id').primary();
      table.string('username').notNullable().unique();
      table.string('password_hash').notNullable();
    });
  }

  // sessionsテーブル
  await db.schema.dropTableIfExists('sessions');
  await db.schema.createTable('sessions', (table) => {
    table.string('sid').primary();
    table.json('sess').notNullable();
    table.dateTime('expired').notNullable(); // ← 'expired' カラム名に変更
  });
}

// サーバー起動前にテーブルセットアップ
await setupTables();

// セッションストアの初期化
const store = new KnexSessionStore({
  knex: db,
  tablename: 'sessions',
  sidfieldname: 'sid',
  createtable: false,
  clearInterval: 60000,
});

app.prepare().then(() => {
  const server = express();

  // CSP header configuration
  server.use((req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    );
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  server.use(express.json());

  // Session middleware configuration
  server.use(
    session({
      secret: process.env.SESSION_SECRET || 'your-super-secret-key',
      resave: false,
      saveUninitialized: false,
      store: store,
      cookie: {
        httpOnly: true,
        secure: !dev,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      },
    })
  );

  // API endpoints for authentication
  server.post('/api/auth/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
      const existingUser = await db('users').where({ username }).first();
      if (existingUser) {
        return res.status(409).json({ success: false, message: 'Username already exists' });
      }

      const saltRounds = 10;
      const password_hash = await bcrypt.hash(password, saltRounds);

      await db('users').insert({ username, password_hash });
      res.status(201).json({ success: true, message: 'User created successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  server.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
      const user = await db('users').where({ username }).first();
      if (user && (await bcrypt.compare(password, user.password_hash))) {
        req.session.userId = user.id;
        return res.status(200).json({ success: true });
      }
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  server.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Logout failed' });
      }
      res.clearCookie('connect.sid');
      res.status(200).json({ success: true });
    });
  });

  // Middleware for protecting routes
  const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    next();
  };

  server.get('/api/dashboard', requireAuth, (req, res) => {
    res.status(200).json({ success: true, message: 'Welcome to the dashboard!', userId: req.session.userId });
  });

  // Next.js のリクエストハンドリング
  server.use((req, res) => {
    return handle(req, res);
  });

  server.listen(port, (err) => {
    if (err) throw err;
    console.log(`> Ready on http://localhost:${port}`);
  });
});
