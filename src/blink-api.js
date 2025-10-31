/* eslint-disable require-jsdoc */
const crypto = require('crypto');
const { URLSearchParams } = require('url');
const { limitedFetch } = require('./util/http');

const { sleep } = require('./utils');
const IniFile = require('./inifile');
const { log } = require('./log');
const { stringify } = require('./stringify');
// const stringify = JSON.stringify;
// crypto.randomBytes(16).toString("hex").toUpperCase().replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5")
const DEFAULT_BLINK_CLIENT_UUID = '1EAF7C88-2AAB-BC51-038D-DB96D6EEE22F';
const BLINK_API_HOST = 'immedia-semi.com';
const DEFAULT_HOST_PREFIX = 'rest-prod';
const DEFAULT_URL = `${DEFAULT_HOST_PREFIX}.${BLINK_API_HOST}`;
const BASE_URL = `https://${DEFAULT_URL}`;
const OAUTH_BASE_URL = 'https://api.oauth.blink.com';
const REFRESH_ENDPOINT = `${OAUTH_BASE_URL}/oauth/token`;
const CACHE = new Map();
const OAUTH_ORIGIN = 'https://api.oauth.blink.com';

function normalizeHeaderMap(source) {
    if (!source || typeof source !== 'object') return null;
    const entries = Object.entries(source);
    if (!entries.length) return null;
    return entries.reduce((acc, [key, value]) => {
        if (value === undefined || value === null || value === '') return acc;
        acc[String(key).toLowerCase()] = String(value);
        return acc;
    }, {});
}

const buildRestBaseUrl = (region = 'prod') => {
    const shard = region && region !== 'prod' ? `rest-${region}` : DEFAULT_HOST_PREFIX;
    return `https://${shard}.${BLINK_API_HOST}`;
};

const DEFAULT_CLIENT_OPTIONS = {
    notificationKey: null,
    appName: 'com.immediasemi.blink',
    device: 'iPhone15,2',
    type: 'ios',
    name: 'iPhone',
    appVersion: '6.32.0 (124007) #0cd7f73de',
    os: '16.7.2',
    userAgent: 'CFNetwork/1490.0.4 Darwin/23.6.0',
    locale: 'en_US',
    timeZone: 'America/New_York',
    oauthScope: 'client offline_access',
    oauthClientId: 'ios',
    oauthClientSecret: 'cBl6zzw1bYw3mjKwHnGXcgZEnKQS68EX',
    hardwareId: DEFAULT_BLINK_CLIENT_UUID,
};

/* eslint-disable */
/**
 * https://github.com/MattTW/BlinkMonitorProtocol
 *
 * List of APIs as of 2022-03
 * /account/delete/
 * /api/v5/account/login
 * /api/v1/account/options
 * /api/v4/account/password_change/
 * /api/v4/account/password_change/pin/generate/
 * /api/v4/account/password_change/pin/verify/
 * /api/v6/account/register
 * /account/system_offline/{network}
 * /api/v1/account/tiv
 * /account/update
 * /api/v3/account/validate_email
 * /api/v3/account/validate_password
 * /api/v1/account/video_options
 * /api/v4/account/{accountId}/client/{clientId}/logout/
 * /api/v4/account/{accountId}/client/{clientId}/email_change/
 * /api/v4/account/{accountId}/client/{clientId}/email_change/pin/resend
 * /api/v4/account/{accountId}/client/{clientId}/email_change/pin/verify/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/pin/generate/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/pin/verify/
 * /api/v4/account/{accountId}/client/{client}/pin/resend/
 * /api/v4/account/{accountId}/client/{client}/pin/verify/
 * /api/v4/account/{accountId}/pin/resend/
 * /api/v4/account/{accountId}/pin/verify/
 * /api/v3/account/{account_id}}/resend_account_verification/
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/pin/resend
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/pin/verify/
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/request_pin/
 * /api/v1/accounts/{accountId}/clients/{client_id}/control_panel/clients
 * /api/v1/accounts/{accountId}/clients/{client_id}/control_panel/delete
 * /api/v1/accounts/{accountId}/clients/{client}/options
 * /api/v1/accounts/{accountId}/country/update/
 * /api/v1/accounts/{accountId}/doorbells/{serial}/fw_update
 * /api/v1/accounts/{accountId}/events/app/
 * /api/v3/accounts/{accountId}/homescreen
 * /api/v1/accounts/{accountId}/info/
 * /api/v2/accounts/{accountId}/media/changed
 * /api/v1/accounts/{accountId}/media/delete
 * /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{camera}/accessories/{accessoryType}/{accessoryId}/delete/
 * /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{camera}/accessories/{accessoryType}/{accessoryId}/lights/{lightControl}
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/change_wifi
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/config
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/delete
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/status
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/thumbnail
 * /api/v1/accounts/{accountId}/networks/{networkId}/state/{type}
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/change_mode
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/change_wifi
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/clear_creds/
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/owl_as_chime/list
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/owl_as_chime/update
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/stay_awake/
 * /api/v1/accounts/{accountId}/networks/{network_id}/state/disarm
 * /api/v6/accounts/{accountId}/networks/{network}/cameras/{camera}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/cameras/{camera}/zones
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/add
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/chime/{chimeType}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/power_test
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/trigger_chime
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/delete
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/disable
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/enable
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/status
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/thumbnail
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/zones
 * /api/v1/accounts/{accountId}/networks/{network}/owls/add
 * /api/v1/accounts/{accountId}/networks/{network}/owls/{owl}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/eject
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/format
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/request/{command}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/request
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/{manifestId}/clip/delete/{clipId}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/{manifestId}/clip/request/{clipId}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/mount
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/status
 * /api/v1/accounts/{accountId}/owls/{serial}/fw_update
 * /api/v1/accounts/{accountId}/subscriptions/clear_popup/{type}
 * /api/v2/accounts/{accountId}/subscriptions/entitlements
 * /api/v1/accounts/{accountId}/subscriptions/link/link_account
 * /api/v1/accounts/{accountId}/subscriptions/link/unlink_account
 * /api/v1/accounts/{accountId}/subscriptions/plans/cancel_trial
 * /api/v1/accounts/{accountId}/subscriptions/plans/get_device_attach_eligibility
 * /api/v1/accounts/{accountId}/subscriptions/plans/renew_trial
 * /api/v1/accounts/{accountId}/subscriptions/plans/{subscription_id}/attach
 * /api/v1/accounts/{accountId}/subscriptions/plans/{subscription}
 * /api/v2/accounts/{accountId}/subscriptions/plans
 * /api/v1/accounts/{accountId}/subscriptions/request/status/{uuid}
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/client_verification/pin/resend/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/client_verification/pin/verify/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/phone_number_change/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/phone_number_change/pin/verify
 * /app/logs/upload/
 * /api/v1/camera/usage
 * /client/{client_id}/update
 * /api/v1/countries/
 * /api/v2/devices/identify/{serialNumber}
 * /api/v1/feature_flags/enabled/
 * /api/v1/fw/app/update_check
 * /network/add
 * /network/{network}/camera/add
 * /api/v1/network/{network}/camera/{camera}/calibrate
 * /network/{network}/camera/{camera}/config
 * /network/{network}/camera/{camera}/delete/
 * /network/{network}/camera/{camera}/status
 * /api/v1/network/{network}/camera/{camera}/temp_alert_disable
 * /api/v1/network/{network}/camera/{camera}/temp_alert_enable
 * /network/{network}/camera/{camera}/thumbnail
 * /network/{network}/camera/{camera}/update
 * /network/{network}/camera/{camera}/{type}
 * /network/{network}/command/{command}/done/
 * /network/{network}/command/{command}/update/
 * /network/{network}/command/{command}
 * /network/{network}/delete
 * /api/v2/network/{network}/sync_module/{type}
 * /network/{network}/syncmodule/{syncmodule}/delete/
 * /network/{network}/update
 * /api/v1/networks/{network}/programs/create
 * /api/v1/networks/{network}/programs/{program}/delete
 * /api/v1/networks/{network}/programs/{program}/disable
 * /api/v1/networks/{network}/programs/{program}/enable
 * /api/v1/networks/{network}/programs/{program}/update
 * /api/v1/networks/{network}/programs
 * /api/v1/networks/{network}/sirens/activate/
 * /api/v1/networks/{network}/sirens/add/
 * /api/v1/networks/{network}/sirens/deactivate/
 * /api/v1/networks/{network}/sirens/
 * /api/v1/networks/{network}/sirens/update
 * /api/v1/networks/{network}/sirens/{siren}/activate/
 * /api/v1/networks/{network}/sirens/{siren}/delete
 * /api/v1/networks/{network}/sirens/{siren}/update
 * /api/v2/notification
 * /regions
 * /api/v1/sirens/
 * /api/v2/support/ob_phone/
 * /api/v1/sync_modules/{serial}/fw_update
 * /api/v1/users/{user_id}/country/update/
 * /api/v1/version
 */
/* eslint-enable */

class BlinkAPI {
    constructor(clientUUID, auth = {}) {
        const {
            path: authPath = '~/.blink',
            section: authSection = 'default',
            ...authOverrides
        } = auth || {};
        const ini = IniFile.read(process.env.BLINK || authPath, process.env.BLINK_SECTION || authSection);

        const resolvedClientUUID = authOverrides.clientUUID
            || clientUUID
            || process.env.BLINK_CLIENT_UUID
            || ini.client
            || DEFAULT_BLINK_CLIENT_UUID;

        const resolvedHardwareId = authOverrides.hardwareId
            || process.env.BLINK_HARDWARE_ID
            || ini.hardware_id
            || resolvedClientUUID;

        const resolvedNotificationKey = authOverrides.notificationKey
            || process.env.BLINK_NOTIFICATION_KEY
            || ini.notification
            || crypto.randomBytes(32).toString('hex');

        this.auth = {
            clientUUID: resolvedClientUUID,
            hardwareId: resolvedHardwareId,
            notificationKey: resolvedNotificationKey,
        };
        const clientOverrides = Object.entries({
            notificationKey: this.auth.notificationKey,
            appName: authOverrides.appName || process.env.BLINK_APP_NAME || ini.app_name,
            device: authOverrides.device || process.env.BLINK_DEVICE || ini.device || ini.device_identifier,
            type: authOverrides.type || process.env.BLINK_CLIENT_TYPE || ini.client_type,
            name: authOverrides.name || process.env.BLINK_CLIENT_NAME || ini.client_name,
            appVersion: authOverrides.appVersion || process.env.BLINK_APP_VERSION || ini.app_version,
            os: authOverrides.os || process.env.BLINK_OS_VERSION || ini.os_version,
            userAgent: authOverrides.userAgent || process.env.BLINK_USER_AGENT || ini.user_agent,
            locale: authOverrides.locale || process.env.BLINK_LOCALE || ini.locale,
            timeZone: authOverrides.timeZone || process.env.BLINK_TIME_ZONE || ini.time_zone,
            oauthScope: authOverrides.oauthScope || process.env.BLINK_OAUTH_SCOPE || ini.oauth_scope,
            oauthClientId: authOverrides.oauthClientId || process.env.BLINK_OAUTH_CLIENT_ID || ini.oauth_client_id,
            oauthClientSecret: authOverrides.oauthClientSecret || process.env.BLINK_OAUTH_CLIENT_SECRET || ini.oauth_client_secret,
            hardwareId: this.auth.hardwareId,
        }).reduce((acc, [key, value]) => {
            if (value !== undefined && value !== null && value !== '') {
                acc[key] = value;
            }
            return acc;
        }, {});
        this._clientOptions = Object.assign({}, DEFAULT_CLIENT_OPTIONS, clientOverrides);
        this._session = null;
        this.refreshToken = null;
        this.tokenExpiresAt = 0;
        this.scope = null;
        this.tokenType = null;
        this.sessionID = null;
        this.tokenHeaders = null;
    }

    set region(val) {
        if (val) this._region = val;
    }

    get region() {
        return process.env.BLINK_REGION || this._region || 'prod';
    }

    set token(val) {
        if (val) this._token = val;
    }

    get token() {
        return this._token;
    }

    hasValidToken(bufferMs = 30000) {
        if (!this.token) return false;
        if (!this.tokenExpiresAt) return true;
        return (Date.now() + bufferMs) < this.tokenExpiresAt;
    }

    canRefresh() {
        return Boolean(this.refreshToken);
    }

    getOAuthBundle() {
        if (!this.token) return null;
        return {
            access_token: this.token,
            refresh_token: this.refreshToken,
            expires_at: this.tokenExpiresAt || 0,
            account_id: this.accountID,
            client_id: this.clientID,
            region: this.region,
            scope: this.scope,
            token_type: this.tokenType,
            session_id: this.sessionID,
            hardware_id: this.auth.hardwareId,
            oauth_client_id: this._clientOptions?.oauthClientId || DEFAULT_CLIENT_OPTIONS.oauthClientId,
            headers: this.tokenHeaders ? Object.assign({}, this.tokenHeaders) : null,
        };
    }

    useOAuthBundle(bundle = {}) {
        if (!bundle?.access_token) return null;
        this.token = bundle.access_token;
        this.refreshToken = bundle.refresh_token || this.refreshToken;
        this.tokenExpiresAt = bundle.expires_at || 0;
        this.accountID = bundle.account_id || this.accountID;
        this.clientID = bundle.client_id || this.clientID;
        this.region = bundle.region || this.region;
        this.scope = bundle.scope || this.scope;
        this.tokenType = bundle.token_type || this.tokenType;
        this.sessionID = bundle.session_id || this.sessionID;
        if (bundle.hardware_id) this.auth.hardwareId = bundle.hardware_id;
        if (bundle.oauth_client_id) {
            const nextOptions = Object.assign({}, this._clientOptions, {
                oauthClientId: bundle.oauth_client_id,
            });
            if (!nextOptions.oauthClientSecret) {
                nextOptions.oauthClientSecret = DEFAULT_CLIENT_OPTIONS.oauthClientSecret;
            }
            this._clientOptions = nextOptions;
        }
        const normalizedHeaders = normalizeHeaderMap(bundle.headers || bundle.token_headers);
        if (normalizedHeaders) {
            this.tokenHeaders = normalizedHeaders;
            if (normalizedHeaders['hardware-id']) {
                this.auth.hardwareId = normalizedHeaders['hardware-id'];
            }
        }
        const account = Object.assign({}, this._session?.account, {
            account_id: this.accountID,
            client_id: this.clientID,
            tier: this.region,
            region: this.region,
        });
        this._session = Object.assign({}, this._session, {
            account,
            auth: Object.assign({}, this._session?.auth, { token: this.token }),
            access_token: this.token,
            refresh_token: this.refreshToken,
            expires_at: this.tokenExpiresAt,
            scope: this.scope,
            token_type: this.tokenType,
            session_id: this.sessionID,
            headers: this.tokenHeaders,
        });
        return this._session;
    }

    _ingestSession(session = {}) {
        if (!session) return this._session;
        const normalized = Object.assign({}, this._session, session);
        const accessToken = session.access_token || session.auth?.token;
        if (!accessToken) {
            this._session = normalized;
            return normalized;
        }

        const refreshToken = session.refresh_token || session.auth?.refresh_token || this.refreshToken;
        const expiresAt = session.expires_at || (session.expires_in
            ? Date.now() + Number(session.expires_in) * 1000
            : this.tokenExpiresAt || 0);
        const scope = session.scope || session.auth?.scope || normalized.scope || this.scope;
        const tokenType = session.token_type || session.auth?.token_type || normalized.token_type || this.tokenType;
        const sessionId = session.session_id || normalized.session_id || this.sessionID;

        const headerSource = session.headers || session.token_headers || normalized.headers;
        const normalizedHeaders = normalizeHeaderMap(headerSource);
        if (normalizedHeaders) {
            this.tokenHeaders = normalizedHeaders;
            if (normalizedHeaders['hardware-id']) {
                this.auth.hardwareId = normalizedHeaders['hardware-id'];
            }
        }

        this.token = accessToken;
        this.refreshToken = refreshToken || this.refreshToken;
        this.tokenExpiresAt = expiresAt || 0;
        if (scope) this.scope = scope;
        if (tokenType) this.tokenType = tokenType;
        if (sessionId) this.sessionID = sessionId;

        let account = {};
        if (normalized.account) account = Object.assign(account, normalized.account);
        if (session.account) account = Object.assign(account, session.account);
        if (!account.account_id) account.account_id = session.account_id ?? this.accountID;
        if (!account.client_id) account.client_id = session.client_id ?? this.clientID;
        if (!account.tier) account.tier = session.region || account.region || this.region;
        if (account.tier && !account.region) account.region = account.tier;
        this.accountID = account.account_id || this.accountID;
        this.clientID = account.client_id || this.clientID;
        this.region = account.tier || account.region || this.region || 'prod';

        normalized.account = account;
        normalized.auth = Object.assign({}, session.auth, {
            token: accessToken,
            refresh_token: refreshToken,
            expires_at: this.tokenExpiresAt,
        });
        normalized.access_token = accessToken;
        normalized.refresh_token = refreshToken;
        normalized.expires_at = this.tokenExpiresAt;
        normalized.scope = this.scope;
        normalized.token_type = this.tokenType;
        normalized.session_id = this.sessionID;
        normalized.headers = this.tokenHeaders;
        normalized.oauth_client_id = this._clientOptions?.oauthClientId;

        this._session = normalized;
        this.init(this.token, this.accountID, this.clientID, this.region);
        return normalized;
    }

    set accountID(val) {
        if (val) this._accountID = val;
    }

    get accountID() {
        return this._accountID;
    }

    set clientID(val) {
        if (val) this._clientID = val;
    }

    get clientID() {
        return this._clientID;
    }

    init(token, accountID, clientID, region = 'prod') {
        this.token = token;
        this.accountID = accountID;
        this.clientID = clientID;
        this.region = region;
    }

    async reset() {
        return reset();
    }

    async get(path = '/', maxTTL = 1, autologin = true, httpErrorAsError = true) {
        return await this._request('GET', path, null, maxTTL, autologin, httpErrorAsError);
    }

    async post(path = '/', body = null, autologin = true, httpErrorAsError = true, options = {}) {
        return this._request('POST', path, body, null, autologin, httpErrorAsError, options);
    }

    async _request(method = 'GET', path = '/', payload = null, maxTTL = null, autologin = true, httpErrorAsError = true,
        options = {}) {
        // first invocation we refresh the API tokens
        if (autologin) await this.login();
        let targetPath = path.replace('{accountID}', this.accountID).replace('{clientID}', this.clientID);
        if (!targetPath.startsWith('http') && !targetPath.startsWith('/')) {
            targetPath = `/${targetPath}`;
        }

        const cacheKey = `${method}:${targetPath}`;
        const now = Date.now();
        if (CACHE.has(cacheKey) && (maxTTL || 0) > 0) {
            const cache = CACHE.get(cacheKey);
            // Fresh?
            if ((cache.expiresAt || 0) > now) {
                return cache.body;
            }
            // Briefly serve stale to avoid thundering herd while one request refreshes.
            if ((cache.cooldownUntil || 0) > now) {
                return cache.body;
            }
            // Set a short cooldown; first requester will refetch.
            cache.cooldownUntil = now + 3000; // 3s stale-while-revalidate
            CACHE.set(cacheKey, cache);
        }

        const client = this._clientOptions || DEFAULT_CLIENT_OPTIONS;
        const buildMatch = /\(([^)]+)\)/.exec(client.appVersion || '');
        const appBuild = buildMatch ? buildMatch[1] : '2703151501';
        const locale = client.locale || 'en_US';
        const timeZone = client.timeZone || 'America/New_York';
        const userAgentSuffix = client.userAgent || 'CFNetwork/1490.0.4 Darwin/23.6.0';
        const headers = {
            'User-Agent': `Blink/${appBuild} ${userAgentSuffix}`,
            'app-build': appBuild,
            'App-Name': client.appName || 'com.immediasemi.blink',
            'App-Version': client.appVersion || DEFAULT_CLIENT_OPTIONS.appVersion,
            'Device-Name': client.device || DEFAULT_CLIENT_OPTIONS.device,
            'OS-Version': client.os || DEFAULT_CLIENT_OPTIONS.os,
            'Locale': locale,
            'x-blink-time-zone': timeZone,
            'accept-language': locale.replace('_', '-') + ', en;q=0.9',
            'Accept': '*/*',
        };
        const extraHeaders = Object.assign({}, options.headers || {});
        const skipAuthHeader = Boolean(options.skipAuthHeader);
        const preferContentType = options.contentType;
        const rawBody = options.rawBody === true;
        const formEncode = options.form === true;
        const includeHeaders = options.includeHeaders === true;
        const requestOptions = { method, headers: Object.assign(headers, extraHeaders) };
        const hasContentType = () => Boolean(requestOptions.headers['Content-Type']);
        const setContentType = value => {
            if (!hasContentType()) requestOptions.headers['Content-Type'] = value;
        };
        if (!skipAuthHeader && this.token) requestOptions.headers['Authorization'] = `Bearer ${this.token}`;

        if (payload !== null && payload !== undefined) {
            if (rawBody) {
                requestOptions.body = payload;
                if (preferContentType) setContentType(preferContentType);
            }
            else if (payload instanceof URLSearchParams) {
                requestOptions.body = payload.toString();
                setContentType(preferContentType || 'application/x-www-form-urlencoded; charset=UTF-8');
            }
            else if (formEncode) {
                const params = payload instanceof URLSearchParams ? payload : new URLSearchParams();
                if (!(payload instanceof URLSearchParams)) {
                    for (const [key, value] of Object.entries(payload || {})) {
                        if (value === undefined || value === null) continue;
                        if (Array.isArray(value)) {
                            value.forEach(entry => params.append(key, String(entry)));
                        }
                        else {
                            params.append(key, String(value));
                        }
                    }
                }
                requestOptions.body = params.toString();
                setContentType(preferContentType || 'application/x-www-form-urlencoded; charset=UTF-8');
            }
            else if (typeof payload === 'string') {
                requestOptions.body = payload;
                if (preferContentType) setContentType(preferContentType);
            }
            else if (Buffer.isBuffer(payload)) {
                requestOptions.body = payload;
                if (preferContentType) setContentType(preferContentType);
            }
            else {
                requestOptions.body = JSON.stringify(payload);
                setContentType(preferContentType || 'application/json');
            }
        }

        // Build the base URL:
        //  - absolute URLs pass through
        //  - tier_info must always hit the prod host regardless of shard
        //  - otherwise, hit the discovered region shard (u003, prde, etc.)
        let requestUrl = targetPath;
        if (!targetPath.startsWith('http')) {
            if (targetPath.startsWith('/oauth/')) {
                requestUrl = `${OAUTH_BASE_URL}${targetPath}`;
            }
            else if (targetPath === '/api/v1/account/tier_info') {
                // Blink expects tier_info on the prod host regardless of shard.
                requestUrl = `${BASE_URL}${targetPath}`;
            } else {
                requestUrl = `${buildRestBaseUrl(this.region || 'prod')}${targetPath}`;
            }
        }
        log.info(`${method} ${requestUrl} @${maxTTL}`);
        log.debug(requestOptions);

        const res = await limitedFetch(requestUrl, requestOptions).catch(async e => {
            if (!/ECONNRESET|ETIMEDOUT|ESOCKETTIMEDOUT|disconnected/.test(e.message)) log.error(e);
            // TODO: handle network errors more gracefully
            if (autologin) return null;
            return Promise.reject(e);
        });

        if (!res || res == {}) {
            await this.login(true); // force a login on network connection loss
            return await this._request(method, path, payload, maxTTL, false, httpErrorAsError, options);
        }

        log.debug(res.status + ' ' + res.statusText);
        log.debug(Object.fromEntries(res.headers.entries()));
        // TODO: deal with network failures

        let respBody;
        const ct = res.headers.get('content-type') || '';
        if (/application\/json/i.test(ct)) {
            respBody = await res.json();
            log.debug(stringify(respBody));
        } else if (/text\//i.test(ct)) {
            respBody = await res.text();
            log.debug(respBody);
        } else {
            respBody = Buffer.from(await res.arrayBuffer());
        }
        if (res.status === 401) {
            // if the API call resulted in 401 Unauthorized (token expired?), try logging in again.
            if (autologin) {
                await this.login(true);
                return this._request(method, path, payload, maxTTL, false, httpErrorAsError, options);
            }
            // fallback
            // TODO: handle error states more gracefully
            const statusMsg = res.headers.get('status') || (res.status + ' ' + res.statusText);
            const logFn = httpErrorAsError ? log.error : log.debug;
            logFn(`${method} ${requestUrl} (${statusMsg})`);
            logFn(respBody ?? Object.fromEntries(res.headers));
            if (httpErrorAsError) {
                throw new Error(res.headers.get('status'));
            }
        }
        else if (res.status >= 500) {
            // TODO: how do we get out of infinite retry?
            log.error(`RETRY: ${method} ${requestUrl} (${res.headers.get('status') || res.status + ' ' + res.statusText})`);
            this.token = null; // force a re-login if 5xx errors
            await sleep(1000);
            return this._request(method, path, payload, maxTTL, false, httpErrorAsError, options);
        }
        else if (res.status === 429) {
            // TODO: how do we get out of infinite retry?
            log.error(`RETRY: ${method} ${requestUrl} (${res.headers.get('status') || res.status + ' ' + res.statusText})`);
            await sleep(500);
            return this._request(method, path, payload, maxTTL, false, httpErrorAsError, options);
        }
        else if (res.status === 409) {
            if (httpErrorAsError) {
                if (!/busy/.test(respBody?.message)) {
                    const status = res.headers.get('status') || res.status + ' ' + res.statusText;
                    throw new Error(`${method} ${requestUrl} (${status})`);
                }
            }
        }
        else if (res.status >= 400) {
            const status = res.headers.get('status') || res.status + ' ' + res.statusText;
            const logFn2 = httpErrorAsError ? log.error : log.debug;
            logFn2(`${method} ${requestUrl} (${status})`);
            logFn2(respBody ?? Object.fromEntries(res.headers));
            if (httpErrorAsError) {
                throw new Error(`${method} ${requestUrl} (${status})`);
            }
        }
        // TODO: what about other 3xx?
        else if (res.status === 200 && method === 'GET') {
            const ttlMs = (maxTTL || 0) * 1000;
            CACHE.set(cacheKey, {
                body: respBody,
                status: res.status,
                headers: Object.fromEntries(res.headers), // informational only
                fetchedAt: now,
                expiresAt: ttlMs ? now + ttlMs : 0,
                cooldownUntil: 0
            });
        }

        if (method !== 'GET') {
            CACHE.delete(`GET:${targetPath}`);
        }
        if (includeHeaders) {
            return {
                body: respBody,
                headers: Object.fromEntries(res.headers.entries()),
                status: res.status,
            };
        }
        return respBody;
    }

    async getUrl(url) {
        return await this.get(`${url}`);
    }

    /**
     *
     * APP CLIENT FUNCTIONS
     *
     **/

    /**
     *
     * POST https://rest-prod.immedia-semi.com/api/v5/account/login
     *
     * :authority:       rest-prod.immedia-semi.com
     * locale:           en_CA
     * content-type:     application/json
     * accept:           * /*
     * app-build:        IOS_124007
     * accept-encoding:  gzip, deflate, br
     * user-agent:       Blink/124007 CFNetwork/1490.0.4 Darwin/23.6.0
     * accept-language:  en-CA
     * content-length:   337
     *
     * {
     *     "app_version": "6.32.0 (124007) #0cd7f73de",
     *     "client_name": "iPhone",
     *     "client_type": "ios",
     *     "device_identifier": "iPhone12,3",
     *     "email": "user@example.com",
     *     "notification_key": "4976d0584130d0122a31887952f778aab5164461fe43db067159dc11da2cb535",
     *     "os_version": "14.2",
     *     "password": "password1",
     *     "unique_id": "6D684F3D-1D86-14F9-B748-15571A3F1FFF"
     * }
     *
     * content-type:            application/json
     * date:                    Fri, 02 Oct 2020 00:26:27 GMT
     * vary:                    Accept-Encoding
     * status:                  200 OK
     * x-blink-served-by:       i-022a33c1836242ee4
     * x-content-type-options:  nosniff
     * x-powered-by:            Phusion Passenger
     * server:                  nginx + Phusion Passenger
     * content-encoding:        gzip
     * x-cache:                 Miss from cloudfront
     * via:                     1.1 2c060d2b820e53bf308fe03fbfaed0e9.cloudfront.net (CloudFront)
     * x-amz-cf-pop:            ATL56-C1
     * x-amz-cf-id:             9gCCfKQ9_aGv53o0Gt75aNVRs0bxiWtkQ_FC-kWYJYLEeihFtm9BAw==
     *
     * {
     *     "account": {
     *        "account_id": 1000001,
     *        "account_verification_required": false,
     *        "client_id": 2360401,
     *        "client_verification_required": true,
     *        "new_account": false,
     *        "phone_verification_required": false,
     *        "region": "ap",
     *        "tier": "prod",
     *        "user_id": 12147,
     *        "verification_channel": "phone"
     *    },
     *    "allow_pin_resend_seconds": 60,
     *    "auth": {
     *        "token": "2YKEsy9BPb9puha1s4uBwe"
     *    },
     *    "force_password_reset": false,
     *    "lockout_time_remaining": 0,
     *    "phone": {
     *        "country_calling_code": "1",
     *        "last_4_digits": "5555",
     *        "number": "+1******5555",
     *        "valid": true
     *    },
     *    "verification": {
     *        "email": {
     *            "required": false
     *        },
     *        "phone": {
     *            "channel": "sms",
     *            "required": true
     *        }
     *    }
     * }
     *
     **/

    async login(force = false, client = DEFAULT_CLIENT_OPTIONS, httpErrorAsError = true) {
        this._clientOptions = Object.assign({}, DEFAULT_CLIENT_OPTIONS, client || {});
        if (!force && this.hasValidToken()) {
            const session = this._session || this._ingestSession({
                access_token: this.token,
                refresh_token: this.refreshToken,
                expires_at: this.tokenExpiresAt,
                account: {
                    account_id: this.accountID,
                    client_id: this.clientID,
                    tier: this.region,
                },
            });
            return session;
        }

        let session;
        if (this.canRefresh()) {
            try {
                session = await this.refreshGrant(this._clientOptions, httpErrorAsError);
                if (session && !(session.access_token || session.auth?.token)) {
                    log.debug('Blink refresh grant returned no access token; treating as failed refresh');
                    session = null;
                }
            } catch (err) {
                log.debug('Blink refresh grant failed:', err?.message || err);
                session = null;
            }
        }

        if (!session) {
            throw new Error('Blink access/refresh tokens are missing or expired. Provide fresh tokens in the Homebridge configuration.');
        }

        if (/unauthorized|invalid/i.test(session?.message)) {
            throw new Error(session.message);
        }

        const normalized = this._ingestSession(session);

        if (!this.region || this.region === 'prod') {
            try {
                const ti = await this.get('/api/v1/account/tier_info', 0, /*autologin*/ false, /*httpErrorAsError*/ false);
                const discovered = ti?.tier || ti?.region || ti?.account?.tier;
                if (discovered && discovered !== this.region) this.region = discovered;
            } catch (e) {
                log.debug('tier_info lookup failed; staying on region:', this.region, e?.message || e);
            }
        }

        return normalized;
    }

    async refreshGrant(client = DEFAULT_CLIENT_OPTIONS, httpErrorAsError = true) {
        if (!this.refreshToken) throw new Error('Missing refresh token');

        const params = new URLSearchParams();
        const add = (key, value) => {
            if (value === undefined || value === null) return;
            params.append(key, String(value));
        };
        const scope = client.oauthScope || 'client offline_access';
        const hardwareId = client.hardwareId || this.auth.hardwareId || this.auth.clientUUID;
        const clientId = client.oauthClientId || this.auth.clientUUID;
        add('grant_type', 'refresh_token');
        add('refresh_token', this.refreshToken);
        add('client_id', clientId);
        add('scope', scope);
        add('client_secret', client.oauthClientSecret);
        add('hardware_id', hardwareId);
        add('unique_id', this.auth.clientUUID);
        add('client_name', client.name);
        add('client_type', client.type);
        add('device_identifier', client.device);
        add('app_name', client.appName);
        add('app_version', client.appVersion);
        add('os_version', client.os);
        add('locale', client.locale);
        add('time_zone', client.timeZone);
        add('notification_key', client.notificationKey || this.auth.notificationKey);

        const response = await this.post(REFRESH_ENDPOINT, params, false, httpErrorAsError, {
            skipAuthHeader: true,
            includeHeaders: true,
        });
        const body = response?.body ?? response;
        if (!body || typeof body !== 'object') {
            return body;
        }
        const headers = normalizeHeaderMap(response?.headers);
        if (headers) body.headers = headers;
        return Object.assign({}, body, { headers });
    }

    /**
     * POST https://rest-prod.immedia-semi.com/api/v4/account/1000001/client/2360401/pin/verify
     * :authority:       rest-prod.immedia-semi.com
     * locale:           en_CA
     * content-type:     application/json
     * accept:           * /*
     * app-build:        IOS_124007
     * token-auth:       2YKEsy9BPb9puha1s4uBwe
     * accept-encoding:  gzip, deflate, br
     * user-agent:       Blink/124007 CFNetwork/1490.0.4 Darwin/23.6.0
     * accept-language:  en-CA
     * content-length:   16
     * {"pin":"123456"}
     *
     * content-type:            application/json
     * date:                    Fri, 02 Oct 2020 00:26:48 GMT
     * vary:                    Accept-Encoding
     * status:                  200 OK
     * x-blink-served-by:       i-084c7f99a490e5cf5
     * x-content-type-options:  nosniff
     * x-powered-by:            Phusion Passenger
     * server:                  nginx + Phusion Passenger
     * content-encoding:        gzip
     * x-cache:                 Miss from cloudfront
     * via:                     1.1 2c060d2b820e53bf308fe03fbfaed0e9.cloudfront.net (CloudFront)
     * x-amz-cf-pop:            ATL56-C1
     * x-amz-cf-id:             lbxn02VW0vtzs3S0QnPnkjdnW5rTyja2ooPMSbQAI3jQjal2O-ynfQ==
     * {
     *     "code": 1626,
     *     "message": "Client has been successfully verified",
     *     "require_new_pin": false,
     *     "valid": true
     * }
     **/
    async verifyPIN(pin, httpAsError = true) {
        if (pin === undefined || pin === null || pin === '') {
            throw new Error('PIN is required for verification');
        }
        const data = {
            pin,
        };
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/pin/verify/`, data, false, httpAsError);
    }

    async resendPIN(httpAsError = true) {
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/pin/resend/`, null, false, httpAsError);
    }

    async logout() {
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/logout/`);
    }

    /**
     * GET https: *rest-prod.immedia-semi.com/api/v1/accounts/1000001/clients/2360401/options
     * {
     *     "options": "eyJuZXR3b3JrX29yZGVyIjpbMTIwOTJd...hbWVyYV9vcmRlciI6eyIxMjA5MiI6WzM2Nzk5LDM2ODE3XX19"
     * }
     *
     * base64 decode:
     * {
     *     "network_order":    [2000001],
     *     "keys":    [
     *         ["client.options.show_homescreen_tutorial_state", "N1"],
     *         ["homescreen.whats_new_last_showed_at", "N20200902"],
     *         ["client.options.show_add_device_tutorial_state", "N1"]
     *     ],
     *     "schema": 1,
     *     "camera_order": {
     *         "2000001" : [4000001, 4000002]
     *     }
     * }
     **/
    async getClientOptions() {
        return await this.get(`/api/v1/accounts/{accountID}/clients/{clientID}/options`);
    }

    async updateClientOptions(clientOptionsResponse) {
        return await this.post(`/api/v1/accounts/{accountID}/clients/{clientID}/options`, clientOptionsResponse);
    }

    /**
     * ACCOUNT
     */

    /*
     *
     * {
     *   "account": {
     *     "id": 1000001,
     *     "email_verified": true,
     *     "email_verification_required": true
     *   },
     *   "networks": [
     *     {
     *       "id": 2000001,
     *       "created_at": "2016-02-13T19:15:54+00:00",
     *       "updated_at": "2020-10-02T00:29:30+00:00",
     *       "name": "82 Downing",
     *       "time_zone": "America/Toronto",
     *       "dst": true,
     *       "armed": false,
     *       "lv_save": false
     *     }
     *   ],
     *   "sync_modules": [
     *     {
     *       "id": 3000001,
     *       "created_at": "2016-02-13T19:17:57+00:00",
     *       "updated_at": "2020-10-03T04:35:46+00:00",
     *       "onboarded": true,
     *       "status": "online",
     *       "name": "Blink SM",
     *       "serial": "A0000001",
     *       "fw_version": "2.13.26",
     *       "type": "sm1",
     *       "last_hb": "2020-10-03T15:44:36+00:00",
     *       "wifi_strength": 1,
     *       "network_id": 2000001,
     *       "enable_temp_alerts": true,
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false,
     *       "local_storage_status": "unavailable"
     *     }
     *   ],
     *   "cameras": [
     *     {
     *       "id": 4000001,
     *       "created_at": "2016-02-13T19:21:09+00:00",
     *       "updated_at": "2020-10-03T14:50:36+00:00",
     *       "name": "Alpha",
     *       "serial": "B0000001",
     *       "fw_version": "2.151",
     *       "type": "white",
     *       "enabled": true,
     *       "thumbnail": "/media/production/account/101/network/2001/camera/4001/clip_HIwo6g_2020_10_02__00_28AM",
     *       "status": "done",
     *       "battery": "ok",
     *       "usage_rate": false,
     *       "network_id": 2000001,
     *       "issues": [],
     *       "signals": {
     *         "lfr": 5,
     *         "wifi": 5,
     *         "temp": 78,
     *         "battery": 3
     *       },
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false
     *     },
     *     {
     *       "id": 13812,
     *       "created_at": "2016-02-13T19:29:36+00:00",
     *       "updated_at": "2020-10-03T11:20:36+00:00",
     *       "name": "Beta",
     *       "serial": "130060596",
     *       "fw_version": "2.151",
     *       "type": "white",
     *       "enabled": true,
     *       "thumbnail": "/media/production/account/1001/network/2001/camera/13812/clip_rHLLGqU_2020_10_02__00_17AM",
     *       "status": "done",
     *       "battery": "ok",
     *       "usage_rate": false,
     *       "network_id": 2000001,
     *       "issues": [],
     *       "signals": {
     *         "lfr": 5,
     *         "wifi": 2,
     *         "temp": 65,
     *         "battery": 3
     *       },
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false
     *     }
     *   ],
     *   "sirens": [],
     *   "chimes": [],
     *   "video_stats": {
     *     "storage": 1,
     *     "auto_delete_days": 365,
     *     "auto_delete_day_options": [3,7,14,30,365]
     *   },
     *   "doorbell_buttons": [],
     *   "owls": [],
     *   "app_updates": {
     *     "message": "OK",
     *     "code": 103,
     *     "update_available": false,
     *     "update_required": false
     *   },
     *   "device_limits": {
     *     "camera": 10,
     *     "chime": 5,
     *     "doorbell_button": 2,
     *     "owl": 10,
     *     "siren": 5,
     *     "total_devices": 20
     *   },
     *   "whats_new": {
     *     "updated_at": 20200902,
     *     "url": "https: *updates.blinkforhome.com/"
     *   }
     * }
     */
    async getAccountHomescreen(maxTTL = 30) {
        return await this.get(`/api/v3/accounts/{accountID}/homescreen`, maxTTL);
    }

    /*
    {
        'id': 12147,
        'created_at': '2016-02-13T19:15:54+00:00',
        'updated_at': '2019-01-06T17:03:28+00:00',
        'email': 'user@example.com',
        'verified': true,
        'verification_required': true,
        'force_password_reset': false,
        'reset_expiration': null,
        'time_zone': 'US/Eastern',
        'owner': true,
        'name': '',
        'user_access': 'write',
        'temp_units': 'f',
        'type': 'regular',
        'pin_created_at': null,
        'pin_failures': 0,
        'account_id': 1000001,
    }
    */
    async getAccount() {
        return await this.get(`/user`);
    }

    /**
     *  {"account":{"id":1000001,"verification_required":false},"client":{"id":9000001,"verification_required":false}}
     */
    async getAccountStatus() {
        return await this.get(`/api/v3/account/{accountID}/status`);
    }

    /**
     * {
     *   "catalina_app_enabled":true,
     *   "sm2_app_enabled":true,
     *   "snapshot_app_enabled":true,
     *   "owl_app_enabled":true,
     *   "legacy_account_mini":true
     * }
     */
    async getAccountOptions() {
        return await this.get(`/api/v1/account/options`);
    }

    /*
    {
        'notifications': {
            'low_battery': true,
            'camera_offline': true,
            'camera_usage': true,
            'scheduling': true,
            'motion': true,
            'sync_module_offline': true,
            'temperature': true,
            'doorbell': true,
            'wifi': true,
            'lfr': true,
            'bandwidth': true,
            'battery_dead': true,
            'local_storage': true,
        },
    }
    */
    async getAccountNotifications() {
        return await this.get(`/api/v1/accounts/{accountID}/notifications/configuration`);
    }

    /**
     * {"notifications":{"camera_usage":true}}
     * {"message":"Client Notification Configure Update Successful"}
     */
    async updateAccountNotifications() {
        return await this.post(`/api/v1/accounts/{accountID}/notifications/configuration`);
    }

    async acknowledgeAccountNotification(notifications = {}) {
        return await this.post(`/api/v2/notification`, notifications);
    }

    async updateAccountVideoOptions(autoPurgeSetterBody) {
        return await this.post(`/api/v1/account/video_options`, autoPurgeSetterBody);
    }

    async updateAccountPassword(changePasswordBody) {
        return await this.post(`/account/change_password/`, changePasswordBody);
    }

    async deleteAccountPassword(resetPasswordBody) {
        return await this.post(`/account/reset_password/`, resetPasswordBody);
    }

    async createAccount(registerAccount) {
        return await this.post(`/api/v4/account/register`, registerAccount);
    }

    async updateAccount(updateAccountBody) {
        return await this.post(`/account/update`, updateAccountBody);
    }

    // async deleteAccount(deleteAccountBody) {
    //     return await this.post(`/account/delete/`, deleteAccountBody);
    // }

    /**
     * MEDIA
     */

    /**
     * {
     *   "limit": 25,
     *   "purge_id": 2139143115,
     *   "refresh_count": 0,
     *   "media": [
     *     {
     *       "id": 2139143346,
     *       "created_at": "2020-10-02T00:28:38+00:00",
     *       "updated_at": "2020-10-02T00:28:57+00:00",
     *       "deleted": false,
     *       "device": "camera",
     *       "device_id": 13812,
     *       "device_name": "Beta",
     *       "network_id": 2000001,
     *       "network_name": "82 Downing",
     *       "type": "video",
     *       "source": "pir",
     *       "watched": false,
     *       "partial": false,
     *       "thumbnail": "/api/v2/accounts/1000001/media/thumb/2139143346",
     *       "media": "/api/v2/accounts/1000001/media/clip/2139143346.mp4",
     *       "additional_devices": [],
     *       "time_zone": "America/Tortola"
     *     }
     *   ]
     * }
     **/
    async getMediaChange(maxTTL = 60, after = '1970-01-01T00:00:01+0000', page = 1) {
        const since = new Date(after);
        return await this.get(`/api/v1/accounts/{accountID}/media/changed?since=${since.toISOString()}&page=${page}`,
            maxTTL);
    }

    async deleteMedia(medialist = []) {
        if (!medialist || medialist.length === 0) return;
        if (!Array.isArray(medialist)) medialist = [medialist];
        return await this.post(`/api/v1/accounts/{accountID}/media/delete`, { media_list: medialist });
    }

    /**
     * COMMAND
     */

    async getCommand(networkID, commandID) {
        return await this.get(`/network/${networkID}/command/${commandID}`);
    }

    async updateCommand(networkID, commandID, updateCommandRequest) {
        return await this.post(`/network/${networkID}/command/${commandID}/update/`, updateCommandRequest);
    }

    async deleteCommand(networkID, commandID) {
        return await this.post(`/network/${networkID}/command/${commandID}/done/`);
    }

    /**
     * PROGRAMS
     */
    async getPrograms(networkID) {
        return await this.get(`/api/v1/networks/${networkID}/programs`);
    }

    /**
     *
     * {
     *     "format": "v1",
     *     "id": 105008,
     *     "name": "Schedule for 82 Downing",
     *     "schedule": [
     *         {
     *             "action": "arm",
     *             "devices": [],
     *             "dow": [
     *                 "sun",
     *                 "wed"
     *             ],
     *             "time": "2020-10-03 04:00:00 +0000"
     *         },
     *         {
     *             "action": "disarm",
     *             "devices": [],
     *             "dow": [
     *                 "sun",
     *                 "wed"
     *             ],
     *             "time": "2020-10-03 05:30:00 +0000"
     *         }
     *     ]
     * }
     **/
    async createProgram(networkID, program) {
        return await this.post(`/api/v1/networks/${networkID}/programs/create`, program);
    }

    async updateProgram(networkID, programID, updateProgramRequest) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/update`, updateProgramRequest);
    }

    async deleteProgram(networkID, prgoramID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${prgoramID}/delete`);
    }

    async disableProgram(networkID, programID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/disable`);
    }

    async enableProgram(networkID, programID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/enable`);
    }

    /**
     * CAMERA
     */

    /**
     * see: SAMPLE.CAMERA_CONFIG
     */
    async getCameraConfig(networkID, cameraID) {
        return await this.get(`/network/${networkID}/camera/${cameraID}/config`);
    }

    /**
     * see: SAMPLE.CAMERA_USAGE
     */
    async getCameraUsage() {
        return await this.get(`/api/v1/camera/usage`);
    }

    /**
     * see: SAMPLE.CAMERA_STATUS
     */
    async getCameraStatus(networkID, cameraID, maxTTL = 60 * 60) {
        return await this.get(`/network/${networkID}/camera/${cameraID}`, maxTTL);
    }

    /**
     * see: SAMPLE.UPDATE_THUMBNAIL
     */
    async updateCameraThumbnail(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/thumbnail`);
    }

    /**
     * see: SAMPLE.UPDATE_CLIP
     */
    async updateCameraClip(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/clip`);
    }

    async deleteCameraClip(clipID) {
        return await this.deleteMedia(clipID);
    }

    /**
     * see: SAMPLE.ENABLE_CAMERA
     */
    async enableCameraMotion(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/enable`);
    }

    /**
     * see: SAMPLE.DISABLE_CAMERA
     */
    async disableCameraMotion(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/disable`);
    }

    // async createCamera(networkID, addCameraBody) {
    //     return await this.post(`/network/${networkID}/camera/add`, addCameraBody);
    // }

    // async deleteCamera(networkID, cameraID) {
    //     return await this.post(`/network/${networkID}/camera/${cameraID}/delete/`);
    // }

    async getCameraMotionRegions(networkID, cameraID) {
        return await this.get(`/api/v1/accounts/{accountID}/networks/${networkID}/cameras/${cameraID}/motion_regions`);
    }

    /**
     * POST {"intent":"liveview","motion_event_start_time":""}
     * {
     *     "command_id": 1023787103,
     *     "continue_interval": 30,
     *     "continue_warning": 10,
     *     "duration": 300,
     *     "extended_duration": 5400,
     *     "join_available": true,
     *     "join_state": "available",
     *     "media_id": null,
     *     "new_command": true,
     *     "options": {},
     *     "polling_interval": 15,
     *     "server": "rtsps://lv2-app-prod.immedia-semi.com:443/iaRAwBZRD_R__IMDS_160060593?client_id=208&blinkRTSP=true",
     *     "submit_logs": true
     * }
     * {"command_id":750082091,"join_available":true,"join_state":"available",
     *   "server":"rtsps://lv2-app-prod.immedia-semi.com:443/NIE5YSJGOOOn__IMDS_B0000001?client_id=208&blinkRTSP=true",
     *   "duration":300,"continue_interval":30,"continue_warning":10,"submit_logs":true,"new_command":true,
     *   "media_id":null,"options":{}}
     * {"complete":false,"status":0,"status_msg":"Command succeeded","status_code":908,
     *   "commands":[{"id":750082091,"created_at":"2020-10-02T00:27:54+00:00","updated_at":"2020-10-02T00:27:56+00:00",
     *      "execute_time":"2020-10-02T00:27:54+00:00","command":"lv_relay","state_stage":"lv",
     *      "stage_rest":"2020-10-02T00:27:54+00:00","stage_cs_db":"2020-10-02T00:27:54+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:54+00:00","stage_sm":"2020-10-02T00:27:54+00:00",
     *       "stage_dev":"2020-10-02T00:27:56+00:00","stage_is":null,"stage_lv":"2020-10-02T00:27:56+00:00",
     *       "stage_vs":null,"state_condition":"running","sm_ack":1,"lfr_ack":0,"sequence":365,"attempts":0,
     *       "transaction":"NIE5Fm36YSJGOOOn","player_transaction":"mrkXahUbYjfbUgHg",
     *      "server":"rtsps://lv2-prod.immedia-semi.com:443/NIE5Fm36YSJGOOOn","duration":300,
     *      "by_whom":"unknown - 6.32.0 (124007) #0cd7f73de - liveview","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,365,205,151,159,167,0]}","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001
     *   }],
     *   "media_id":null
     * }
     * {"complete":true,"status":0,"status_msg":"Command succeeded","status_code":908,
     *  "commands":[{
     *      "id":750082091,"created_at":"2020-10-02T00:27:54+00:00","updated_at":"2020-10-02T00:27:56+00:00",
     *      "execute_time":"2020-10-02T00:27:54+00:00","command":"lv_relay","state_stage":"lv",
     *      "stage_rest":"2020-10-02T00:27:54+00:00","stage_cs_db":"2020-10-02T00:27:54+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:54+00:00","stage_sm":"2020-10-02T00:27:54+00:00",
     *      "stage_dev":"2020-10-02T00:27:56+00:00","stage_is":null,"stage_lv":"2020-10-02T00:27:56+00:00",
     *      "stage_vs":null,"state_condition":"done","sm_ack":1,"lfr_ack":0,"sequence":365,"attempts":0,
     *      "transaction":"NIE5Fm36YSJGOOOn","player_transaction":"mrkXahUbYjfbUgHg",
     *      "server":"rtsps://lv2-prod.immedia-semi.com:443/NIE5Fm36YSJGOOOn","duration":9,
     *      "by_whom":"unknown - 6.32.0 (124007) #0cd7f73de - liveview","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,365,205,151,159,167,0]},LV907","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001}],"media_id":null}
     **/
    async getCameraLiveViewV6(networkID, cameraID) {
        const data = {
            'intent': 'liveview',
            'motion_event_start_time': '',
        };
        return await this.post(`/api/v6/accounts/{accountID}/networks/${networkID}/cameras/${cameraID}/liveview`, data);
    }

    /**
     * see: SAMPLE.CAMERA_STATUS
     */
    async updateCameraStatus(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/status`);
    }

    /**
     * POST {"temp_max":88,"id":4000001,"current_temp":73,"temp_min":50,"network":2000001}
     * {"complete":true,"status":0,"status_msg":"Command succeeded","status_code":908,
     *  "commands":[{"id":750081889,"created_at":"2020-10-02T00:27:08+00:00","updated_at":"2020-10-02T00:27:11+00:00",
     *      "execute_time":"2020-10-02T00:27:08+00:00","command":"temp_calibrate","state_stage":"dev",
     *      "stage_rest":"2020-10-02T00:27:08+00:00","stage_cs_db":"2020-10-02T00:27:09+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:09+00:00","stage_sm":"2020-10-02T00:27:09+00:00",
     *      "stage_dev":"2020-10-02T00:27:11+00:00","stage_is":null,"stage_lv":null,"stage_vs":null,
     *      "state_condition":"done","sm_ack":1,"lfr_ack":0,"sequence":360,"attempts":0,"transaction":"sf61Hj9V8tVDNU",
     *      "player_transaction":"vwL7YY0xf9-d3Vpq","server":null,"duration":73,
     *      "by_whom":"unknown - 6.32.0 (124007) #0cd7f73de","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,360,205,147,159,165,0]}","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001
     *   }],
     *   "media_id":null}
     * {"id":750081889,"created_at":"2020-10-02T00:27:08+00:00","updated_at":"2020-10-02T00:27:08+00:00",
     *      "execute_time":"2020-10-02T00:27:08+00:00","command":"temp_calibrate","state_stage":"rest",
     *      "stage_rest":"2020-10-02T00:27:08+00:00","stage_cs_db":null,"stage_cs_sent":null,"stage_sm":null,
     *      "stage_dev":null,"stage_is":null,"stage_lv":null,"stage_vs":null,"state_condition":"new","sm_ack":null,
     *      "lfr_ack":null,"sequence":null,"attempts":0,"transaction":"sf61Hj9V8FstVDNU",
     *      "player_transaction":"vwL7YY0xf9-d3Vpq","server":null,"duration":73,
     *      "by_whom":"unknown - 6.32.0 (124007) #0cd7f73de","diagnostic":false,"debug":"","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001}
     */
    async updateCameraTemperature(networkID, cameraID, currentTempF, minTempF, maxTempF) {
        // {"temp_max":88,"id":4000001,"current_temp":73,"temp_min":50,"network":2000001}
        const body = {
            'temp_max': maxTempF,
            'id': cameraID,
            'current_temp': currentTempF,
            'temp_min': minTempF,
            'network': networkID,
        };
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/calibrate`, body);
    }

    /**
     * {"video_quality":"standard","record_audio_enable":true,"illuminator_enable":0,"video_length":30,
     *  "early_termination":true,"name":"Alpha","motion_sensitivity":5,"illuminator_intensity":7,"motion_alert":false,
     *  "lfr_sync_interval":8,"alert_interval":10}
     * {"id":750081909,"created_at":"2020-10-02T00:27:14+00:00","updated_at":"2020-10-02T00:27:14+00:00",
     *    "execute_time":"2020-10-02T00:27:14+00:00","command":"config_set","state_stage":"rest",
     *    "stage_rest":"2020-10-02T00:27:14+00:00","stage_cs_db":null,"stage_cs_sent":null,"stage_sm":null,
     *    "stage_dev":null,"stage_is":null,"stage_lv":null,"stage_vs":null,"state_condition":"new","sm_ack":null,
     *    "lfr_ack":null,"sequence":null,"attempts":0,"transaction":"iPYvI_VT4Dovb","player_transaction":"s0OXguCLB74",
     *    "server":null,"duration":null,"by_whom":"unknown - 6.32.0 (124007) #0cd7f73de","diagnostic":false,"debug":"",
     *    "opts_1":0,"target":"camera","target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,
     *    "firmware_id":null,"network_id":2000001,"account_id":1000001,"sync_module_id":3000001}
     **/
    async updateCameraSettings(networkID, cameraID, updateCameraBody) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/update`, updateCameraBody);
    }

    async updateCameraMotionRegions(networkID, cameraID, motionRegions) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/cameras/${cameraID}/motion_regions`,
            motionRegions);
    }

    async disableCameraTempAlert(networkID, cameraID) {
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/temp_alert_disable`);
    }

    async enableCameraTempAlert(networkID, cameraID) {
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/temp_alert_enable`);
    }

    /**
     * see: SAMPLE.CAMERA_SIGNALS
     */
    async getCameraSignals(networkID, cameraID) {
        return await this.get(`/network/${networkID}/camera/${cameraID}/signals`);
    }

    /**
     * SIREN
     */

    async getSirens() {
        return await this.get(`/sirens`);
    }

    async getNetworkSirens(networkID) {
        return await this.get(`/api/v1/networks/${networkID}/sirens/`);
    }

    async activateSiren(networkID, sirenID, duration = 30) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/activate/`, { duration });
    }

    async activateSirens(networkID, duration = 30) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/activate/`, { duration });
    }

    // async createSiren(networkID, addSirenNetworkBody) {
    //     return await this.post(`/api/v1/networks/${networkID}/sirens/add/`, addSirenNetworkBody);
    // }

    async deactivateSirens(networkID) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/deactivate/`);
    }

    // async deleteSirens(networkID, sirenID) {
    //     return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/delete`);
    // }

    async updateSiren(networkID, sirenID, sirenNameBody) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/update`, sirenNameBody);
    }

    async updateSirens(networkID, sirenDurationBody) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/update`, sirenDurationBody);
    }

    /**
     * CHIME
     */

    async createChime(networkID, addSirenNetworkBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/chimes/add/`, addSirenNetworkBody);
    }

    /**
     * OWL
     */

    /**
     * see: SAMPLE.OWL_CONFIG
     */
    async getOwlConfig(networkID, owlID) {
        return await this.get(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/config`);
    }

    async getOwlLiveView(networkID, owlID, liveViewBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/liveview`,
            liveViewBody);
    }

    async updateOwlStatus(networkID, owlID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/status`);
    }

    async updateOwlSettings(networkID, owlID, updateOwlBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/config`, updateOwlBody);
    }

    async updateOwlThumbnail(networkID, owlID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/thumbnail`);
    }

    // async createOwl(networkID, addOwlBody) {
    //     return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/add`, addOwlBody);
    // }

    async changeOwlWifi(networkID, owlID, onboardingStartRequest) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/change_wifi`,
            onboardingStartRequest);
    }

    // async deleteOwl(networkID, owlID) {
    //     return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/delete`);
    // }

    // async addOwl(networkID, onboardingStartRequest) {
    //    return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/add`, onboardingStartRequest);
    // }

    /**
     * METWORK
     */

    /**
     * see: SAMPLE.NETWORKS
     */
    async getNetworks() {
        return await this.get(`/networks`);
    }

    /**
     * see: SAMPLE.ARM_NETWORK
     */
    async armNetwork(networkID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/state/arm`);
    }

    /**
     * see: SAMPLE.DISARM_NETWORK
     */
    async disarmNetwork(networkID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/state/disarm`);
    }

    // async createNetwork(addNetworkBody) {
    //     return await this.post(`/network/add`, addNetworkBody);
    // }

    // async deleteNetwork(networkID) {
    //     return await this.post(`/network/${networkID}/delete`);
    // }

    /**
     * POST {"dst":true,"lv_mode":"relay","time_zone":"America\/Toronto"}
     * {"dst":true,"lv_mode":"relay","time_zone":"America\/Toronto"}
     * {"network":{"id":2000001,"created_at":"2016-02-13T19:15:54+00:00","updated_at":"2020-10-02T00:29:30+00:00",
     *   "deleted_at":null,"name":"82 Downing","network_key":"hifSnlicp+k4bLA=","description":"",
     *   "network_origin":"normal","locale":"","time_zone":"America/Toronto","dst":true,"ping_interval":60,
     *   "encryption_key":null,"armed":false,"autoarm_geo_enable":false,"autoarm_time_enable":false,"lv_mode":"relay",
     *   "lfr_channel":0,"video_destination":"server","storage_used":0,"storage_total":0,"video_count":0,
     *   "video_history_count":4000,"sm_backup_enabled":false,"arm_string":"Disarmed","busy":false,"camera_error":false,
     *   "sync_module_error":false,"feature_plan_id":null,"account_id":1000001,"lv_save":false}}
     **/
    async updateNetwork(networkID, updateNetworkSaveAllLiveViews) {
        return await this.post(`/network/${networkID}/update`, updateNetworkSaveAllLiveViews);
    }

    /**
     * see: SAMPLE.DEVICE
     */
    async getDevice(serialNumber) {
        return await this.get(`/api/v1/devices/identify/${serialNumber}`);
    }

    // async addSyncModuleDevice(networkID, type, onboardingStartRequest) {
    //     return await this.post(`/api/v2/network/${networkID}/sync_module/${type}`);
    // }

    // async deleteSyncModule(networkID, syncModuleID) {
    //     return await this.post(`/network/${networkID}/syncmodule/${syncModuleID}/delete/`);
    // }

    async updateSystem(networkID, updateSystemNameBody) {
        return await this.post(`/network/${networkID}/update`, updateSystemNameBody);
    }

    async updateNetworkTimezone(networkID, updateTimezoneBody) {
        return await this.post(`/network/${networkID}/update`, updateTimezoneBody);
    }

    /**
     * BLINK CORE
     */

    /**
     * see: SAMPLE.BLINK_STATUS
     */
    async getBlinkStatus(tier = 'prod') {
        return await this.get(`https://blinkstatus.net/api/v1/${tier}`);
    }

    /**
     * see: SAMPLE.BLINK_SUPPORT
     */
    async getBlinkSupport() {
        return await this.get(`/api/v2/support/ob_phone/`);
    }

    /**
     * see: SAMPLE.BLINK_APP_VERSION
     */
    async getBlinkAppVersion() {
        return await this.get(`/api/v1/version`);
    }

    /**
     * see: SAMPLE.BLINK_REGIONS
     */
    async getBlinkRegions(country = 'US') {
        return await this.get(`/regions?locale=${country}`);
    }

    async getSyncModuleFirmware(serial) {
        return await this.get(`/api/v1/sync_modules/${serial}/fw_update`);
    }

    async getOwlFirmware(serial) {
        return await this.get(`/api/v1/accounts/{accountID}/owls/${serial}/fw_update`);
    }

    async getAppStatus(serial) {
        return await this.get(`/api/v1/fw/app/update_check?serial=${serial}`);
    }
}

module.exports = BlinkAPI;
