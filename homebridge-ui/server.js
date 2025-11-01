const { URLSearchParams } = require('url');
const { HomebridgePluginUiServer } = require('@homebridge/plugin-ui-utils');
const { log: sharedLog } = require('../src/log');
const BlinkAPI = require('../src/blink-api');
const { randomUUID } = require('crypto');

const REFRESH_ENDPOINT = 'https://api.oauth.blink.com/oauth/token';
const DEFAULT_SCOPE = 'client offline_access';
const DEFAULT_CLIENT_ID = 'ios';
const DEFAULT_CLIENT_SECRET = 'cBl6zzw1bYw3mjKwHnGXcgZEnKQS68EX';
const ANDROID_CLIENT_ID = 'android';
const IOS_UA = 'Blink/49.2 (iPhone; iOS 26.1; Scale/3.00)';
const IOS_HEADERS = {
    'User-Agent': IOS_UA,
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'https://api.oauth.blink.com',
    'Referer': 'https://api.oauth.blink.com/'
};

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

function normalizeString(value) {
    if (value === undefined || value === null) return '';
    if (typeof value !== 'string') return String(value);
    return value.trim();
}

function toNumber(value) {
    const str = normalizeString(value);
    if (!str) return null;
    if (!/^-?\d+$/.test(str)) return str;
    const parsed = Number(str);
    return Number.isNaN(parsed) ? null : parsed;
}

function collectHeaders(response) {
    const headers = {};
    if (!response?.headers) return headers;
    for (const [key, value] of response.headers.entries()) {
        headers[key.toLowerCase()] = value;
    }
    return headers;
}

function mergeHeaderFields(bundle = {}, headers = {}) {
    const preferred = new Map([
        ['account_id', ['account-id', 'x-account-id']],
        ['client_id', ['client-id', 'x-client-id']],
        ['region', ['region', 'x-region']],
        ['token_type', ['token-type', 'x-token-type']],
        ['session_id', ['session-id', 'x-session-id']],
        ['hardware_id', ['hardware-id', 'x-hardware-id']],
        ['scope', ['scope']],
    ]);

    for (const [target, options] of preferred.entries()) {
        if (bundle[target]) continue;
        for (const headerKey of options) {
            const headerValue = headers[headerKey];
            if (headerValue !== undefined && headerValue !== null && headerValue !== '') {
                const normalized = toNumber(headerValue);
                bundle[target] = normalized;
                break;
            }
        }
    }

    if (!bundle.region && bundle.scope && /rest-(\w+)/.test(bundle.scope)) {
        bundle.region = RegExp.$1;
    }

    return bundle;
}

class PluginUiServer extends HomebridgePluginUiServer {
    constructor(customLog) {
        super();

        this.loggerOutput = createLoggerOutputs(customLog);
        const logFn = (...args) => this.loggerOutput.call(...args);
        logFn.error = (...args) => this.loggerOutput.error(...args);
        logFn.info = (...args) => this.loggerOutput.info(...args);
        logFn.debug = (...args) => this.loggerOutput.debug(...args);
        logFn.warn = (...args) => this.loggerOutput.warn(...args);
        this.log = logFn;

        this.onRequest('/tokens/normalize', async payload => {
            try {
                this.log.info('/tokens/normalize requested');
                return await this.handleNormalizeRequest(payload);
            } catch (err) {
                this.log.error('/tokens/normalize error:', err);
                throw err;
            }
        });

        this.onRequest('/tokens/refresh', async payload => {
            try {
                this.log.info('/tokens/refresh requested');
                return await this.handleRefreshRequest(payload);
            } catch (err) {
                this.log.error('/tokens/refresh error:', err);
                throw err;
            }
        });

        this.onRequest('/tokens/login', async payload => {
            try {
                this.log.info('/tokens/login requested');
                return await this.handleLoginRequest(payload);
            } catch (err) {
                this.log.error('/tokens/login error:', err);
                throw err;
            }
        });

        this.ready();
    }

    async handleNormalizeRequest(payload = {}) {
        const accessToken = normalizeString(payload.accessToken || payload.access_token);
        const refreshToken = normalizeString(payload.refreshToken || payload.refresh_token);
        const expiresAt = payload.expires_at || payload.tokenExpiresAt || null;
        const hardwareId = normalizeString(payload.hardwareId || payload.hardware_id);
        const scope = normalizeString(payload.scope);
        const oauthClientId = normalizeString(payload.oauthClientId || payload.oauth_client_id) || DEFAULT_CLIENT_ID;

        return {
            status: 'ok',
            tokens: {
                access_token: accessToken || null,
                refresh_token: refreshToken || null,
                expires_at: expiresAt ? Number(expiresAt) : null,
                account_id: toNumber(payload.accountId || payload.account_id),
                client_id: toNumber(payload.clientId || payload.client_id),
                region: normalizeString(payload.region) || null,
                hardware_id: hardwareId || null,
                scope: scope || null,
                token_type: normalizeString(payload.tokenType || payload.token_type) || 'Bearer',
                session_id: normalizeString(payload.sessionId || payload.session_id) || null,
                headers: payload.tokenHeaders || payload.headers || null,
                oauth_client_id: oauthClientId,
            },
        };
    }

    async handleRefreshRequest(payload = {}) {
        const refreshToken = normalizeString(payload.refreshToken || payload.refresh_token);
        if (!refreshToken) {
            throw new Error('Refresh token is required to request new Blink credentials.');
        }

        const hardwareId = normalizeString(payload.hardwareId || payload.hardware_id);
        const scope = normalizeString(payload.scope);
        const requestedClientId = normalizeString(payload.clientId || payload.client_id);
        const requestedClientSecret = normalizeString(payload.clientSecret || payload.client_secret);

        const attempts = [];
        const addAttempt = (clientId, clientSecret, label) => {
            if (!clientId) return;
            const key = `${clientId}::${clientSecret || ''}`;
            if (attempts.some(entry => entry.key === key)) return;
            attempts.push({ clientId, clientSecret, label, key });
        };

        const resolveSecret = (clientId, secret) => {
            if (secret) return secret;
            if (clientId === DEFAULT_CLIENT_ID) return DEFAULT_CLIENT_SECRET;
            return secret || null;
        };

        if (requestedClientId) {
            addAttempt(requestedClientId, resolveSecret(requestedClientId, requestedClientSecret), 'requested-client');
        }
        addAttempt(ANDROID_CLIENT_ID, null, 'android-client');
        addAttempt(DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET, 'default-client');

        let lastError = null;
        for (const attempt of attempts) {
            const params = new URLSearchParams();
            params.append('grant_type', 'refresh_token');
            params.append('refresh_token', refreshToken);
            params.append('client_id', attempt.clientId);
            const effectiveSecret = resolveSecret(attempt.clientId, attempt.clientSecret);
            if (effectiveSecret) {
                params.append('client_secret', effectiveSecret);
            }
            if (scope || DEFAULT_SCOPE) {
                params.append('scope', scope || DEFAULT_SCOPE);
            }
            if (hardwareId) {
                params.append('hardware_id', hardwareId);
            }

            const response = await fetch(REFRESH_ENDPOINT, {
                method: 'POST',
                headers: {
                    ...IOS_HEADERS,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                },
                body: params,
            });

            const rawBody = await response.json().catch(() => ({}));
            if (!response.ok) {
                const reason = rawBody?.error_description || rawBody?.error || response.statusText;
                lastError = new Error(reason || 'Blink token refresh failed.');
                this.log.debug(`Blink token refresh attempt ${attempt.label || attempt.clientId} failed: ${lastError.message}`);
                continue;
            }

            const headers = collectHeaders(response);
            const expiresIn = Number(rawBody?.expires_in || headers['expires-in'] || 0);
            const expiresAt = rawBody?.expires_at
                ? Number(rawBody.expires_at)
                : (expiresIn > 0 ? Date.now() + expiresIn * 1000 : null);

            const tokens = mergeHeaderFields({
                access_token: rawBody?.access_token || null,
                refresh_token: rawBody?.refresh_token || refreshToken || null,
                expires_at: expiresAt,
                account_id: toNumber(rawBody?.account_id),
                client_id: toNumber(rawBody?.client_id),
                region: rawBody?.region || null,
                scope: rawBody?.scope || scope,
                token_type: rawBody?.token_type || headers['token-type'] || 'Bearer',
                session_id: rawBody?.session_id || headers['session-id'] || null,
                hardware_id: rawBody?.hardware_id || hardwareId || headers['hardware-id'] || null,
            }, headers);

            tokens.oauth_client_id = attempt.clientId;

            return {
                status: 'ok',
                tokens,
                headers,
                raw: rawBody,
            };
        }

        throw lastError || new Error('Blink token refresh failed.');
    }

    async handleLoginRequest(payload = {}) {
        const username = normalizeString(payload.username || payload.email);
        const password = normalizeString(payload.password);
        if (!username || !password) {
            throw new Error('Blink username and password are required to request new tokens.');
        }

        const pin = normalizeString(payload.pin);
        const otp = normalizeString(payload.otp || payload.twoFactorCode || payload.twoFactorToken);
        let hardwareId = normalizeString(payload.hardwareId || payload.hardware_id);
        const refreshToken = normalizeString(payload.refreshToken || payload.refresh_token);
        const accessToken = normalizeString(payload.accessToken || payload.access_token);
        const tokenExpiresAt = payload.tokenExpiresAt ?? payload.expires_at ?? null;

        const clientUUID = hardwareId || normalizeString(payload.clientUUID) || randomUUID().toUpperCase();
        if (!hardwareId) hardwareId = clientUUID;

        const authOverrides = {
            clientUUID,
            hardwareId,
            email: username,
            password,
        };
        if (pin) authOverrides.pin = pin;
        if (otp) authOverrides.otp = otp;
        if (refreshToken) authOverrides.refreshToken = refreshToken;
        if (accessToken) authOverrides.accessToken = accessToken;
        if (tokenExpiresAt) authOverrides.expires_at = tokenExpiresAt;

        const api = new BlinkAPI(clientUUID, authOverrides);
        let session;
        try {
            session = await api.login(true, null, false);
        } catch (err) {
            throw new Error(err?.message || 'Blink authentication failed. Check credentials and 2FA inputs.');
        }

        const bundle = api.getOAuthBundle();
        if (!bundle || !bundle.access_token) {
            throw new Error('Blink did not return a valid access token. Verify your credentials and 2FA information.');
        }

        const responseHeaders = session?.headers || session?.token_headers || bundle.headers || null;

        return {
            status: 'ok',
            tokens: mergeHeaderFields({ ...bundle }, responseHeaders || {}),
            headers: responseHeaders,
            raw: session,
        };
    }
}

module.exports = PluginUiServer;

function startPluginUiServer() { return new PluginUiServer(); }
if (require.main === module) { startPluginUiServer(); }
