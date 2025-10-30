const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
const { HomebridgePluginUiServer } = require('@homebridge/plugin-ui-utils');

const OAUTH_AUTHORIZE_URL = 'https://api.oauth.blink.com/oauth/v2/authorize';
const OAUTH_TOKEN_URL = 'https://api.oauth.blink.com/oauth/token';
const CALLBACK_PATH = '/blink/oauth/callback';
const SESSION_TTL_MS = 5 * 60 * 1000;

class PluginUiServer extends HomebridgePluginUiServer {
    constructor() {
        super();

        this.sessions = new Map();

        this.onRequest('/oauth/start', this.handleOAuthStart.bind(this));
        this.onRequest('/oauth/status', this.handleOAuthStatus.bind(this));

        this.ready();
    }

    async handleOAuthStart(payload = {}) {
        const port = Number(payload.redirectPort || 52888);
        if (!Number.isInteger(port) || port < 1025 || port > 65535) {
            throw new Error('Redirect port must be between 1025 and 65535.');
        }

        const protocol = this.normalizeProtocol(payload.redirectProtocol);
        const host = payload.redirectHost || 'localhost';
        const redirectUri = `${protocol}//${host}:${port}${CALLBACK_PATH}`;
        const hardwareId = payload.hardwareId || crypto.randomUUID();
        const clientId = payload.clientId || 'ios';
        const scope = payload.scope || 'client offline_access';

        const sessionId = crypto.randomUUID();
        const state = crypto.randomBytes(16).toString('hex');
        const codeVerifier = this.buildCodeVerifier();
        const codeChallenge = this.buildCodeChallenge(codeVerifier);

        const session = {
            id: sessionId,
            state,
            codeVerifier,
            clientId,
            scope,
            redirectUri,
            hardwareId,
            createdAt: Date.now(),
            status: 'pending',
            timeout: null,
            server: null,
        };

        await this.startCallbackServer(session, port);

        const query = new URLSearchParams({
            response_type: 'code',
            client_id: clientId,
            redirect_uri: redirectUri,
            scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            hardware_id: hardwareId,
            app_brand: payload.appBrand || 'blink',
            app_version: payload.appVersion || '49.2',
            device_brand: payload.deviceBrand || 'Homebridge',
            device_model: payload.deviceModel || 'Homebridge',
            device_os_version: payload.deviceOsVersion || `Node ${process.versions.node}`,
            entry_source: 'homebridge',
        });

        const authUrl = `${OAUTH_AUTHORIZE_URL}?${query.toString()}`;

        this.sessions.set(sessionId, session);
        session.timeout = setTimeout(() => this.failSession(sessionId, 'Timed out waiting for Blink OAuth callback.'), SESSION_TTL_MS);

        return { sessionId, authUrl, hardwareId };
    }

    async handleOAuthStatus(payload = {}) {
        const session = payload.sessionId && this.sessions.get(payload.sessionId);
        if (!session) {
            return { status: 'expired' };
        }
        if (session.status === 'complete') {
            this.sessions.delete(payload.sessionId);
            return {
                status: 'complete',
                hardwareId: session.hardwareId,
                tokens: session.tokens,
            };
        }
        if (session.status === 'error') {
            this.sessions.delete(payload.sessionId);
            return {
                status: 'error',
                message: session.error,
            };
        }
        return { status: 'pending' };
    }

    normalizeProtocol(input) {
        if (typeof input !== 'string' || !input.trim()) return 'http:';
        const value = input.endsWith(':') ? input : `${input}:`;
        return ['http:', 'https:'].includes(value) ? value : 'http:';
    }

    buildCodeVerifier() {
        return crypto.randomBytes(64).toString('base64url');
    }

    buildCodeChallenge(verifier) {
        return crypto.createHash('sha256').update(verifier).digest('base64url');
    }

    async startCallbackServer(session, port) {
        const server = http.createServer((req, res) => this.handleCallbackRequest(session.id, req, res));
        await new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(port, '0.0.0.0', resolve);
        });
        session.server = server;
    }

    async handleCallbackRequest(sessionId, req, res) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            this.respond(res, 410, 'Blink session expired. Close this tab and retry from Homebridge.');
            return;
        }

        try {
            const url = new URL(req.url, session.redirectUri);
            if (url.pathname !== CALLBACK_PATH) {
                this.respond(res, 404, 'Not Found');
                return;
            }

            const returnedState = url.searchParams.get('state');
            const code = url.searchParams.get('code');
            if (returnedState !== session.state) {
                this.failSession(sessionId, 'State mismatch in Blink OAuth callback.');
                this.respond(res, 400, 'Blink OAuth failed: state mismatch. Close this tab and try again.');
                return;
            }
            if (!code) {
                this.failSession(sessionId, 'Missing authorization code in Blink callback.');
                this.respond(res, 400, 'Blink OAuth failed: missing authorization code.');
                return;
            }

            this.respond(res, 200, '<h1>Success!</h1><p>You can close this window and return to Homebridge.</p>');
            await this.exchangeCode(session, code);
        } catch (err) {
            this.failSession(sessionId, err?.message || 'Unexpected Blink OAuth error.');
            this.respond(res, 500, 'Blink OAuth flow encountered an unexpected error.');
        } finally {
            this.teardownSessionServer(sessionId);
        }
    }

    respond(res, statusCode, body) {
        res.writeHead(statusCode, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<html><body>${body}</body></html>`);
    }

    async exchangeCode(session, code) {
        try {
            const body = new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                client_id: session.clientId,
                redirect_uri: session.redirectUri,
                code_verifier: session.codeVerifier,
                scope: session.scope,
                hardware_id: session.hardwareId,
            });
            const response = await fetch(OAUTH_TOKEN_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body,
            });
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                const error = data?.error_description || data?.error || response.statusText;
                throw new Error(error || 'Blink token exchange failed.');
            }
            const expiresAt = data.expires_in ? Date.now() + Number(data.expires_in) * 1000 : null;
            session.tokens = {
                access_token: data.access_token,
                refresh_token: data.refresh_token,
                expires_at: expiresAt,
                scope: data.scope,
                token_type: data.token_type,
                session_id: data.session_id,
                account_id: data.account_id ?? null,
                client_id: data.client_id ?? null,
                region: data.region ?? null,
            };
            session.status = 'complete';
            this.clearTimeout(session);
        } catch (err) {
            this.failSession(session.id, err?.message || 'Blink token exchange failed.');
        }
    }

    failSession(sessionId, message) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        session.status = 'error';
        session.error = message;
        this.clearTimeout(session);
        this.teardownSessionServer(sessionId);
        this.log(`Blink OAuth session ${sessionId} failed: ${message}`);
    }

    teardownSessionServer(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        if (session.server) {
            session.server.close();
            session.server = null;
        }
    }

    clearTimeout(session) {
        if (session.timeout) {
            clearTimeout(session.timeout);
            session.timeout = null;
        }
    }
}

function startPluginUiServer() {
    return new PluginUiServer();
}

startPluginUiServer();
