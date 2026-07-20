import { OAuth2Client } from 'google-auth-library';

export type GoogleIdentity = {
  sub: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
};

export function googleConfigured(): boolean {
  return Boolean(process.env.GOOGLE_CLIENT_ID);
}

export async function verifyGoogleCredential(credential: string): Promise<GoogleIdentity> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) throw new Error('GOOGLE_CLIENT_ID is not set');

  const client = new OAuth2Client(clientId);
  const ticket = await client.verifyIdToken({
    idToken: credential,
    audience: clientId,
  });
  const payload = ticket.getPayload();
  if (!payload?.sub) throw new Error('Invalid Google token');

  return {
    sub: payload.sub,
    email: payload.email ?? null,
    emailVerified: Boolean(payload.email_verified),
    name: payload.name ?? null,
  };
}
