import { neon } from '@neondatabase/serverless';

// Export a function to get the Neon client using env
export function getSql(env: { DATABASE_URL: string }) {
  return neon(env.DATABASE_URL);
}