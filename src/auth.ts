import bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify, JWTPayload } from 'jose';

export function getAuthHelpers(env: { JWT_SECRET?: string }) {
  const JWT_SECRET = new TextEncoder().encode(env.JWT_SECRET || 'supersecret');

  async function hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async function comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async function signJWT(payload: JWTPayload): Promise<string> {
    return await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('7d')
      .sign(JWT_SECRET);
  }

  async function verifyJWT(token: string): Promise<any> {
    try {
      const { payload } = await jwtVerify(token, JWT_SECRET);
      return payload;
    } catch (e) {
      return null;
    }
  }

  return { hashPassword, comparePassword, signJWT, verifyJWT };
}
