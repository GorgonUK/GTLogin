import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

import {
  createPeer,
  dbConfigured,
  findPeerByGoogleSub,
  findPeerByGrowId,
  linkGoogle,
  updatePeerPassword,
} from './lib/db.js';
import { googleConfigured, verifyGoogleCredential } from './lib/google.js';
import {
  passwordHash,
  passwordVerify,
  randomSessionPassword,
  suggestGrowIdFromEmail,
} from './lib/password.js';

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

function buildToken(parts: {
  _token: string;
  growId: string;
  password: string;
  email?: string;
  reg: 0 | 1;
}): string {
  const base = `_token=${parts._token}&growId=${parts.growId}&password=${parts.password}`;
  const withEmail = parts.email ? `${base}&email=${parts.email}` : base;
  return Buffer.from(`${withEmail}&reg=${parts.reg}`).toString('base64');
}

function sendLoginSuccess(
  res: Response,
  token: string,
  accountType: 'growtopia' | 'google' = 'growtopia',
) {
  res.setHeader('Content-Type', 'application/json');
  res.send(
    JSON.stringify({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType,
    }),
  );
}

function sendLoginFailed(res: Response, message: string, httpStatus = 200) {
  // Growtopia WebView expects HTTP 200 with status != success
  res.status(httpStatus).setHeader('Content-Type', 'application/json');
  res.send(
    JSON.stringify({
      status: 'failed',
      message,
      token: '',
      url: '',
      accountType: 'growtopia',
    }),
  );
}

/**
 * Native form handoff after AJAX/Google auth.
 * Growtopia only continues when the WebView navigates to a real JSON response
 * (document.write leaves raw JSON on screen and the client never proceeds).
 */
app.all('/player/growid/login/handoff', async (req: Request, res: Response) => {
  try {
    const raw = (req.body as Record<string, string>)?.payload || '';
    const data = JSON.parse(raw) as Record<string, unknown>;
    if (data.status !== 'success' || typeof data.token !== 'string' || !data.token) {
      return sendLoginFailed(res, 'Invalid login handoff.');
    }
    res.setHeader('Content-Type', 'application/json');
    res.send(
      JSON.stringify({
        status: 'success',
        message: typeof data.message === 'string' ? data.message : 'Account Validated.',
        token: data.token,
        url: '',
        accountType: typeof data.accountType === 'string' ? data.accountType : 'growtopia',
      }),
    );
  } catch (error) {
    console.log(`[ERROR handoff]: ${error}`);
    return sendLoginFailed(res, 'Login handoff failed.');
  }
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

/** Public config for the dashboard (Google client id, etc.). */
app.get('/player/login/config', (_req: Request, res: Response) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || '',
    googleEnabled: googleConfigured(),
    dbConfigured: dbConfigured(),
  });
});

app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';

  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');
  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent
    .replace(/\{\{\s*data\s*\}\}/g, encodedClientData)
    .replace(/\{\{\s*google_client_id\s*\}\}/g, process.env.GOOGLE_CLIENT_ID || '');

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const _token = formData._token || '';
    const growId = (formData.growId || '').trim();
    const password = formData.password || '';
    const email = (formData.email || '').trim();
    const isRegister = Boolean(email);

    if (!growId || !password) {
      return sendLoginFailed(res, 'GrowID and password are required.');
    }
    if (!/^[A-Za-z0-9]+$/.test(growId) || growId.length > 18) {
      return sendLoginFailed(res, 'GrowID must be letters/numbers only (max 18).');
    }

    if (!dbConfigured()) {
      // Fallback: legacy always-success (game server still verifies). Prefer setting MYSQL_*.
      console.warn('[WARN] MYSQL_* not set — skipping credential check at login page');
      const token = buildToken({
        _token,
        growId,
        password,
        email: isRegister ? email : undefined,
        reg: isRegister ? 1 : 0,
      });
      return sendLoginSuccess(res, token);
    }

    const existing = await findPeerByGrowId(growId);

    if (isRegister) {
      if (existing) {
        return sendLoginFailed(res, 'That GrowID is already taken.');
      }
      if (!email.includes('@')) {
        return sendLoginFailed(res, 'A valid email is required to register.');
      }
      await createPeer(growId, passwordHash(password), email, null);
      const token = buildToken({ _token, growId, password, email, reg: 1 });
      return sendLoginSuccess(res, token);
    }

    if (!existing) {
      return sendLoginFailed(res, 'GrowID not found. Register an account first.');
    }
    if (!existing.password || !passwordVerify(password, existing.password)) {
      return sendLoginFailed(res, 'Incorrect password.');
    }

    const token = buildToken({ _token, growId, password, reg: 0 });
    return sendLoginSuccess(res, token);
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    return sendLoginFailed(res, 'Internal Server Error', 500);
  }
});

/**
 * Google Sign-In: verify GIS credential, create/link peer, return growId token.
 * Body: { credential, _token, growId? } — growId required on first Google login.
 */
app.all('/player/growid/login/google', async (req: Request, res: Response) => {
  try {
    if (!googleConfigured()) {
      return sendLoginFailed(res, 'Google Sign-In is not configured on this server.');
    }
    if (!dbConfigured()) {
      return sendLoginFailed(res, 'Database is not configured; Google Sign-In requires MYSQL_*.');
    }

    const body = req.body as Record<string, string>;
    const credential = body.credential || '';
    const _token = body._token || '';
    const requestedGrowId = (body.growId || '').trim();

    if (!credential) {
      return sendLoginFailed(res, 'Missing Google credential.');
    }

    const identity = await verifyGoogleCredential(credential);
    if (identity.email && !identity.emailVerified) {
      return sendLoginFailed(res, 'Google email is not verified.');
    }

    let peer = await findPeerByGoogleSub(identity.sub);
    const sessionPassword = randomSessionPassword();
    const hashed = passwordHash(sessionPassword);

    if (!peer) {
      let growId = requestedGrowId;
      if (!growId) {
        res.setHeader('Content-Type', 'application/json');
        return res.send(
          JSON.stringify({
            status: 'need_growid',
            message: 'Choose a GrowID for this Google account.',
            suggestedGrowId: suggestGrowIdFromEmail(identity.email || identity.sub),
            email: identity.email || '',
            token: '',
            url: '',
            accountType: 'google',
          }),
        );
      }
      if (!/^[A-Za-z0-9]+$/.test(growId) || growId.length > 18) {
        return sendLoginFailed(res, 'GrowID must be letters/numbers only (max 18).');
      }

      const byName = await findPeerByGrowId(growId);
      if (byName) {
        // Allow linking if the player also proves password ownership via form — not here.
        return sendLoginFailed(res, 'That GrowID is already taken. Pick another name.');
      }

      await createPeer(growId, hashed, identity.email, identity.sub);
      peer = await findPeerByGoogleSub(identity.sub);
    } else {
      await updatePeerPassword(peer.growid, hashed);
      if (!peer.google_sub) {
        await linkGoogle(peer.growid, identity.sub, identity.email);
      }
    }

    if (!peer) {
      return sendLoginFailed(res, 'Could not create Google-linked account.');
    }

    const token = buildToken({
      _token,
      growId: peer.growid,
      password: sessionPassword,
      email: identity.email || undefined,
      reg: 0,
    });
    return sendLoginSuccess(res, token, 'google');
  } catch (error) {
    console.log(`[ERROR google]: ${error}`);
    const msg = error instanceof Error ? error.message : String(error);
    if (/ETIMEDOUT|ECONNREFUSED|ENOTFOUND|connect/i.test(msg)) {
      return sendLoginFailed(
        res,
        'Login server cannot reach the game database. Ask an admin to open MariaDB for Vercel.',
      );
    }
    return sendLoginFailed(res, 'Google Sign-In failed. Try again.');
  }
});

app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData: string | undefined;
    let source = 'empty';
    const contentType = req.headers['content-type'] || '';

    if (typeof req.body === 'object' && req.body !== null) {
      const formData = req.body as Record<string, string>;

      if ('refreshToken' in formData || 'clientData' in formData) {
        refreshToken = formData.refreshToken;
        clientData = formData.clientData;
        source = contentType.includes('application/json') ? 'json/object' : 'form-urlencoded';
      } else if (Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || undefined;
        clientData = params.get('clientData') || undefined;
        if (refreshToken || clientData) {
          source = 'single-key-form-payload';
        }
      }
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      const params = new URLSearchParams(req.body);
      refreshToken = params.get('refreshToken') || undefined;
      clientData = params.get('clientData') || undefined;
      source = 'string/body-parser';
    }

    if ((!refreshToken || !clientData) && req.readable && !req.readableEnded) {
      const rawBody = await new Promise<string>((resolve, reject) => {
        let rawPayload = '';
        req.on('data', (chunk: Buffer | string) => {
          rawPayload += chunk.toString();
        });
        req.on('end', () => resolve(rawPayload));
        req.on('error', reject);
      });

      if (rawBody) {
        const params = new URLSearchParams(rawBody);
        refreshToken = params.get('refreshToken') || refreshToken;
        clientData = params.get('clientData') || clientData;
        if (refreshToken || clientData) {
          source = 'raw-stream';
        }
      }
    }

    console.log(`[CHECKTOKEN] Parsed as ${source}`);

    if (!refreshToken || !clientData) {
      console.log(`[ERROR]: Missing refreshToken or clientData`);
      res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
      return;
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');

    if (decodedRefreshToken.includes('&reg=0')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=0', '');
    } else if (decodedRefreshToken.includes('&reg=1')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=1', '');
    }

    // Optional: re-verify password in token against DB so stolen/stale tokens fail early
    if (dbConfigured()) {
      const growMatch = decodedRefreshToken.match(/growId=([^&]*)/);
      const passMatch = decodedRefreshToken.match(/password=([^&]*)/);
      const growId = growMatch?.[1] ? decodeURIComponent(growMatch[1]) : '';
      const password = passMatch?.[1] ? decodeURIComponent(passMatch[1]) : '';
      if (growId && password) {
        const peer = await findPeerByGrowId(growId);
        if (!peer?.password || !passwordVerify(password, peer.password)) {
          return sendLoginFailed(res, 'Session expired. Please log in again.');
        }
      }
    }

    const token = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');

    res.setHeader('Content-Type', 'application/json');
    res.send(
      JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
        accountAge: 2,
      }),
    );
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(200).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
  console.log(`[SERVER] DB: ${dbConfigured() ? 'configured' : 'NOT configured (password check skipped)'}`);
  console.log(`[SERVER] Google: ${googleConfigured() ? 'enabled' : 'disabled'}`);
});

export default app;
