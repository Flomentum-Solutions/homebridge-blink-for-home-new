const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
const { HomebridgePluginUiServer } = require('@homebridge/plugin-ui-utils');
const { log: sharedLog } = require('../src/log');

const OAUTH_AUTHORIZE_URL = 'https://api.oauth.blink.com/oauth/v2/authorize';
const OAUTH_SIGNIN_URL = 'https://api.oauth.blink.com/oauth/v2/signin';
const OAUTH_TOKEN_URL = 'https://api.oauth.blink.com/oauth/token';
const CALLBACK_PATH = '/blink/oauth/callback';
const SESSION_TTL_MS = 5 * 60 * 1000;

function createLoggerOutputs(candidate) {
    const fallback = sharedLog || console;
    const source = candidate || fallback;

    const call = typeof source === 'function'
        ? (...args) => source(...args)
        : (...args) => fallback(...args);

    const error = typeof source.error === 'function'
        ? source.error.bind(source)
        : (typeof fallback.error === 'function' ? fallback.error.bind(fallback) : call);

    const info = typeof source.info === 'function'
        ? source.info.bind(source)
        : (typeof fallback.info === 'function' ? fallback.info.bind(fallback) : call);

    const debug = typeof source.debug === 'function'
        ? source.debug.bind(source)
        : info;

    const warn = typeof source.warn === 'function'
        ? source.warn.bind(source)
        : error;

    return { call, error, info, debug, warn };
}

class PluginUiServer extends HomebridgePluginUiServer {
    constructor(customLog) {
        super();

        this.loggerOutput = createLoggerOutputs(customLog);
        this.logLevel = 'verbose';

        const logFn = (...args) => this.loggerOutput.call(...args);
        logFn.error = (...args) => this.loggerOutput.error(...args);
        logFn.info = (...args) => {
            if (this.isVerbose()) {
                this.loggerOutput.info(...args);
            }
        };
        logFn.debug = (...args) => {
            if (this.isDebug()) {
                this.loggerOutput.debug(...args);
            }
        };
        logFn.warn = (...args) => this.loggerOutput.warn(...args);
        this.log = logFn;

        this.log.info('PluginUiServer constructor called with customLog:', !!customLog);

        this.sessions = new Map();

        this.onRequest('/oauth/start', async (payload) => {
            try { this.log.info('/oauth/start requested, payload:', JSON.stringify(payload ?? {})); } catch {}
            try {
                return await this.handleOAuthStart(payload);
            } catch (err) {
                this.log.error('/oauth/start handler error:', err);
                throw err;
            }
        });
        
        this.onRequest('/oauth/status', async (payload) => {
            try { this.log.info('/oauth/status requested, payload:', JSON.stringify(payload ?? {})); } catch {}
            try {
                return await this.handleOAuthStatus(payload);
            } catch (err) {
                this.log.error('/oauth/status handler error:', err);
                throw err;
            }
        });

        this.ready();
    }

    // helper: try listening on a port; resolves with server and port if successful, rejects if error
    tryListen(server, port, host = '127.0.0.1') {
        return new Promise((resolve, reject) => {
            server.once('error', err => {
            server.removeAllListeners('listening');
            reject(err);
            });
            server.once('listening', () => {
            server.removeAllListeners('error');
            resolve({ server, port });
            });
            server.listen(port, host);
        });
    }

    // helper: attempt to find a free port starting from basePort, up to some limit
    async findFreePort(basePort = 1025, host = '127.0.0.1', maxPort = 65535) {
        let port = basePort;
        while (port <= maxPort) {
            const server = http.createServer();  // simple server to test binding
            try {
                const result = await this.tryListen(server, port, host);
                // close that test server, we will reuse port for real server
                result.server.close();
                return port;
            } catch (err) {
                if (err.code === 'EADDRINUSE') {
                    port++;
                    continue;
                }
                // some other error - throw
                throw err;
            }
        }
        throw new Error(`No free port found in range ${basePort}-${maxPort}`);
    }

    async handleOAuthStart(payload = {}) {
        this.setLogLevel(payload.logging);

        const requestedPort = Number(payload.redirectPort || 52888);
        if (!Number.isInteger(requestedPort) || requestedPort < 1025 || requestedPort > 65535) {
            throw new Error('Redirect port must be between 1025 and 65535.');
        }

        const protocol = this.normalizeProtocol(payload.redirectProtocol);
        const host = payload.redirectHost || 'localhost';

        const hardwareId = payload.hardwareId || crypto.randomUUID();
        const clientId = 'ios';
        const scope = 'client';
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
          hardwareId,
          createdAt: Date.now(),
          status: 'pending',
          timeout: null,
          server: null,
          redirectUri: null,
          callbackPort: null,
          tokens: null,
          error: null,
        };

        this.sessions.set(sessionId, session);

        // find free port & spin listener
        await this.startCallbackServer(session, requestedPort);

        // Now that session.callbackPort is set:
        const actualPort = session.callbackPort;
        const redirectUri = `${protocol}//${host}:${actualPort}${CALLBACK_PATH}`;
        session.redirectUri = redirectUri;

        // Then build query using redirectUri
        const query = new URLSearchParams({
            response_type: 'code',
            client_id: clientId,
            redirect_uri: redirectUri,
            scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            hardware_id: hardwareId,
            app_brand: 'blink',
            app_version: '49.2',
            device_brand: 'Apple',
            device_model: 'iPhone18,1',
            device_os_version: '26.1',
        });

        const authUrl = `${OAUTH_SIGNIN_URL}?${query.toString()}`;

        this.log.debug("Constructed Auth URL: ", authUrl);

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

    setLogLevel(level) {
        const setting = typeof level === 'string' ? level.toLowerCase() : '';
        if (setting === 'debug') {
            this.logLevel = 'debug';
        }
        else if (setting === 'verbose') {
            this.logLevel = 'verbose';
        }
        else {
            this.logLevel = 'error';
        }
    }

    isVerbose() {
        return this.logLevel === 'verbose' || this.logLevel === 'debug';
    }

    isDebug() {
        return this.logLevel === 'debug';
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

    async startCallbackServer(session, requestedPort) {
        const host = '127.0.0.1';
        let port = Number(requestedPort || 52888);

        this.log.info(`Attempting to start callback server for session ${session.id} starting at port ${port}`);

        try {
            port = await this.findFreePort(port, host);
        } catch (err) {
            this.log.error(`Unable to find free port for OAuth callback server: ${err.message}`);
            throw err;
        }

        const server = http.createServer((req, res) => this.handleCallbackRequest(session.id, req, res));
        try {
            await new Promise((resolve, reject) => {
            server.once('error', err => {
                reject(err);
            });
            server.once('listening', () => {
                resolve();
            });
            server.listen(port, host);
            });
        } catch (err) {
            this.log.error(`Failed to start callback server on port ${port}: ${err.message}`);
            throw err;
        }
        session.server = server;
        session.callbackPort = port;
        this.log.debug(`Callback server listening on ${host}:${port}`);
    }

    async handleCallbackRequest(sessionId, req, res) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            this.log.debug("Blink session expired. Close this tab and retry from Homebridge.", req.url);
            this.respond(res, 410, 'Blink session expired. Close this tab and retry from Homebridge.');
            return;
        }

        try {
            const url = new URL(req.url, session.redirectUri);
            if (url.pathname !== CALLBACK_PATH) {
                this.log.debug("Not Found", req.url);
                this.respond(res, 404, 'Not Found');
                return;
            }

            const returnedState = url.searchParams.get('state');
            const code = url.searchParams.get('code');
            if (returnedState !== session.state) {
                this.log.debug("State mismatch in Blink OAuth callback.", req.url);
                this.failSession(sessionId, 'State mismatch in Blink OAuth callback.');
                this.respond(res, 400, 'Blink OAuth failed: state mismatch. Close this tab and try again.');
                return;
            }
            if (!code) {
                this.log.debug("Missing authorization code in Blink callback.", req.url);
                this.failSession(sessionId, 'Missing authorization code in Blink callback.');
                this.respond(res, 400, 'Blink OAuth failed: missing authorization code.');
                return;
            }
            this.log.debug("Success!", req.url);
            this.respond(res, 200, '<h1>Success!</h1><p>You can close this window and return to Homebridge.</p>');
            await this.exchangeCode(session, code);
        } catch (err) {
            this.log.debug("Unexpected Error", req.url);
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
        this.log.error(`Blink OAuth session ${sessionId} failed: ${message}`);
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

module.exports = PluginUiServer;

function startPluginUiServer() { return new PluginUiServer(); }
if (require.main === module) { startPluginUiServer(); }