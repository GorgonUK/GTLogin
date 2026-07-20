import mysql, { type Pool, type RowDataPacket, type ResultSetHeader } from 'mysql2/promise';

export type PeerRow = {
  uid: number;
  growid: string;
  password: string | null;
  google_sub: string | null;
  email: string | null;
};

let pool: Pool | null = null;

export function dbConfigured(): boolean {
  return Boolean(process.env.MYSQL_HOST && process.env.MYSQL_USER && process.env.MYSQL_DATABASE);
}

export function getPool(): Pool {
  if (!dbConfigured()) {
    throw new Error('Database is not configured (set MYSQL_HOST, MYSQL_USER, MYSQL_DATABASE, MYSQL_PASSWORD).');
  }
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.MYSQL_HOST,
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD || '',
      database: process.env.MYSQL_DATABASE,
      waitForConnections: true,
      connectionLimit: 4,
      connectTimeout: 8_000,
      enableKeepAlive: true,
      ssl: process.env.MYSQL_SSL === '1' ? { rejectUnauthorized: false } : undefined,
    });
  }
  return pool;
}

export async function findPeerByGrowId(growId: string): Promise<PeerRow | null> {
  const [rows] = await getPool().query<RowDataPacket[]>(
    'SELECT uid, growid, password, google_sub, email FROM peer WHERE growid = ? LIMIT 1',
    [growId],
  );
  return (rows[0] as PeerRow | undefined) ?? null;
}

export async function findPeerByGoogleSub(googleSub: string): Promise<PeerRow | null> {
  const [rows] = await getPool().query<RowDataPacket[]>(
    'SELECT uid, growid, password, google_sub, email FROM peer WHERE google_sub = ? LIMIT 1',
    [googleSub],
  );
  return (rows[0] as PeerRow | undefined) ?? null;
}

export async function createPeer(growId: string, passwordHash: string, email?: string | null, googleSub?: string | null): Promise<void> {
  await getPool().query<ResultSetHeader>(
    'INSERT INTO peer (growid, password, email, google_sub) VALUES (?, ?, ?, ?)',
    [growId, passwordHash, email ?? null, googleSub ?? null],
  );
}

export async function updatePeerPassword(growId: string, passwordHash: string): Promise<void> {
  await getPool().query<ResultSetHeader>('UPDATE peer SET password = ? WHERE growid = ?', [
    passwordHash,
    growId,
  ]);
}

export async function linkGoogle(growId: string, googleSub: string, email: string | null): Promise<void> {
  await getPool().query<ResultSetHeader>(
    'UPDATE peer SET google_sub = ?, email = COALESCE(?, email) WHERE growid = ?',
    [googleSub, email, growId],
  );
}
