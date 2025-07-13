import { Hono } from 'hono';
import { getSql } from './db';
import { getAuthHelpers } from './auth';

const app = new Hono();

// Register User
app.post('/auth/register', async (c) => {
  const env = c.env;
  const sql = getSql(env);
  const { hashPassword, signJWT } = getAuthHelpers(env);
  const { name, email, phone_number, password, confirm_password, profile_image_url } = await c.req.json();
  if (!name || !email || !password || !confirm_password) {
    return c.json({ error: 'INVALID_INPUT' }, 400);
  }
  if (password !== confirm_password) {
    return c.json({ error: 'INVALID_INPUT', message: 'Passwords do not match' }, 400);
  }
  // Check if email exists
  const existing = await sql`SELECT id FROM users WHERE email = ${email}`;
  if (existing.length > 0) {
    return c.json({ error: 'EMAIL_ALREADY_EXISTS' }, 409);
  }
  if (password.length < 8) {
    return c.json({ error: 'WEAK_PASSWORD', message: 'Password must be at least 8 characters' }, 400);
  }
  const password_hash = await hashPassword(password);
  const [user] = await sql`INSERT INTO users (name, email, phone_number, password_hash, profile_image_url) VALUES (${name}, ${email}, ${phone_number}, ${password_hash}, ${profile_image_url}) RETURNING id, name, email, phone_number, profile_image_url, created_at`;
  const token = await signJWT({ userId: user.id, email: user.email });
  return c.json({ message: 'User registered', user: user, token }, 201);
});

// Login User
app.post('/auth/login', async (c) => {
  const env = c.env;
  const sql = getSql(env);
  const { comparePassword, signJWT } = getAuthHelpers(env);
  const { email, password } = await c.req.json();
  if (!email || !password) {
    return c.json({ error: 'INVALID_INPUT' }, 400);
  }
  const users = await sql`SELECT * FROM users WHERE email = ${email}`;
  if (users.length === 0) {
    return c.json({ error: 'INVALID_CREDENTIALS' }, 401);
  }
  const user = users[0];
  const valid = await comparePassword(password, user.password_hash);
  if (!valid) {
    return c.json({ error: 'INVALID_CREDENTIALS' }, 401);
  }
  const token = await signJWT({ userId: user.id, email: user.email });
  // Exclude sensitive info
  const { password_hash, ...userProfile } = user;
  return c.json({ message: 'Login successful', user: userProfile, token });
});

// Logout User (stateless JWT, just return 204)
app.post('/auth/logout', (c) => {
  return c.body(null, 204);
});

// Auth middleware
async function getUserFromAuth(c) {
  const env = c.env;
  const { verifyJWT } = getAuthHelpers(env);
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const payload = await verifyJWT(token);
  if (!payload || !payload.userId) return null;
  return payload;
}

// Fetch User Profile
app.get('/user/profile', async (c) => {
  const env = c.env;
  const sql = getSql(env);
  const payload = await getUserFromAuth(c);
  if (!payload) {
    return c.json({ error: 'UNAUTHORIZED' }, 401);
  }
  const users = await sql`SELECT id, name, email, phone_number, profile_image_url, created_at FROM users WHERE id = ${payload.userId}`;
  if (users.length === 0) {
    return c.json({ error: 'USER_NOT_FOUND' }, 404);
  }
  return c.json({ user: users[0] });
});

// Debug endpoint to test DB connection
app.get('/debug/db', async (c) => {
  try {
    const sql = getSql(c.env);
    const result = await sql`SELECT 1 as test`;
    return c.json({ success: true, result });
  } catch (err) {
    return c.json({ success: false, error: (err as Error).message }, 500);
  }
});

app.get('/debug/env', (c) => {
  return c.json({ DATABASE_URL: c.env.DATABASE_URL || 'not set' });
});

export default app;
