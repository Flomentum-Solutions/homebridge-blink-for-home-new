const { URLSearchParams } = require('url');
const { HomebridgePluginUiServer } = require('@homebridge/plugin-ui-utils');
const { log: sharedLog } = require('../src/log');

const REFRESH_ENDPOINT = 'https://api.oauth.blink.com/oauth/refresh';
const DEFAULT_SCOPE = 'client offline_access';
const DEFAULT_CLIENT_ID = 'blink/com.immediasemi.ios.blink';
const DEFAULT_CLIENT_SECRET = 'cBl6zzw1bYw3mjKwHnGXcgZEnKQS68EX';
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

        this.ready();
    }

    async handleNormalizeRequest(payload = {}) {
        const accessToken = normalizeString(payload.accessToken || payload.access_token);
        const refreshToken = normalizeString(payload.refreshToken || payload.refresh_token);
        const expiresAt = payload.expires_at || payload.tokenExpiresAt || null;
        const hardwareId = normalizeString(payload.hardwareId || payload.hardware_id);
        const scope = normalizeString(payload.scope) || DEFAULT_SCOPE;

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
                scope,
                token_type: normalizeString(payload.tokenType || payload.token_type) || 'Bearer',
                session_id: normalizeString(payload.sessionId || payload.session_id) || null,
                headers: payload.tokenHeaders || payload.headers || null,
            },
        };
    }

    async handleRefreshRequest(payload = {}) {
        const refreshToken = normalizeString(payload.refreshToken || payload.refresh_token);
        if (!refreshToken) {
            throw new Error('Refresh token is required to request new Blink credentials.');
        }

        const hardwareId = normalizeString(payload.hardwareId || payload.hardware_id);
        const clientId = normalizeString(payload.clientId || payload.client_id) || DEFAULT_CLIENT_ID;
        const clientSecret = normalizeString(payload.clientSecret || payload.client_secret) || DEFAULT_CLIENT_SECRET;
        const scope = normalizeString(payload.scope) || DEFAULT_SCOPE;

        const params = new URLSearchParams();
        params.append('grant_type', 'refresh_token');
        params.append('refresh_token', refreshToken);
        params.append('client_id', clientId);
        params.append('client_secret', clientSecret);
        params.append('scope', scope);
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
            throw new Error(reason || 'Blink token refresh failed.');
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

        return {
            status: 'ok',
            tokens,
            headers,
            raw: rawBody,
        };
    }
}

module.exports = PluginUiServer;

function startPluginUiServer() { return new PluginUiServer(); }
if (require.main === module) { startPluginUiServer(); }
