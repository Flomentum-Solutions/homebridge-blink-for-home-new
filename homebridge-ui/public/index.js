(() => {
    const ui = window.homebridge;
    const toast = {
        success(message) {
            if (ui.toast?.success) ui.toast.success(message);
            else console.info(message);
        },
        error(message) {
            if (ui.toast?.error) ui.toast.error(message);
            else console.error(message);
        },
    };

    const state = {
        config: {},
        busy: false,
    };

    const statusEl = document.getElementById('status');
    const accessInput = document.getElementById('access-token');
    const refreshInput = document.getElementById('refresh-token');
    const hardwareInput = document.getElementById('hardware-id');
    const expiryEl = document.getElementById('detail-expiry');
    const hardwareSummaryEl = document.getElementById('detail-hardware');
    const accountEl = document.getElementById('detail-account');
    const clientEl = document.getElementById('detail-client');
    const regionEl = document.getElementById('detail-region');
    const scopeEl = document.getElementById('detail-scope');
    const typeEl = document.getElementById('detail-type');
    const sessionEl = document.getElementById('detail-session');
    const oauthClientEl = document.getElementById('detail-oauth-client');
    const headersEl = document.getElementById('detail-headers');
    const saveButton = document.getElementById('save-tokens');
    const refreshButton = document.getElementById('refresh-tokens');
    const clearButton = document.getElementById('clear-tokens');

    function formatExpiry(timestamp) {
        if (!timestamp) return '—';
        const date = new Date(Number(timestamp));
        if (Number.isNaN(date.getTime())) return '—';
        const minutes = Math.max(0, Math.round((timestamp - Date.now()) / 60000));
        return `${date.toLocaleString()} (${minutes} min)`;
    }

    function formatHeaders(headers) {
        if (!headers || typeof headers !== 'object') return '—';
        const entries = Object.entries(headers).filter(([, value]) => value !== undefined && value !== null && value !== '');
        if (!entries.length) return '—';
        return `${entries.length} header${entries.length === 1 ? '' : 's'}`;
    }

    function updateStatus() {
        const hasAccess = Boolean(state.config.accessToken);
        const hasRefresh = Boolean(state.config.refreshToken);
        let status = 'Tokens missing';
        if (hasAccess && hasRefresh) status = 'Tokens saved';
        else if (hasRefresh) status = 'Access token missing';
        statusEl.textContent = status;

        hardwareInput.placeholder = state.config.hardwareId || 'Blink hardware UUID';
        expiryEl.textContent = state.config.tokenExpiresAt ? formatExpiry(state.config.tokenExpiresAt) : '—';
        hardwareSummaryEl.textContent = state.config.hardwareId || '—';
        accountEl.textContent = state.config.accountId ? `Account ${state.config.accountId}` : '—';
        clientEl.textContent = state.config.clientId ? `Client ${state.config.clientId}` : '—';
        regionEl.textContent = state.config.region || '—';
        scopeEl.textContent = state.config.tokenScope || '—';
        typeEl.textContent = state.config.tokenType || '—';
        oauthClientEl.textContent = state.config.oauthClientId || '—';
        sessionEl.textContent = state.config.sessionId || '—';
        headersEl.textContent = formatHeaders(state.config.tokenHeaders);
    }

    function syncFormFromConfig() {
        hardwareInput.value = state.config.hardwareId || '';
        accessInput.value = state.config.accessToken || '';
        refreshInput.value = state.config.refreshToken || '';
    }

    function getFormValues() {
        return {
            hardwareId: hardwareInput.value.trim(),
            accessToken: accessInput.value.trim(),
            refreshToken: refreshInput.value.trim(),
        };
    }

    function setBusy(isBusy) {
        state.busy = isBusy;
        saveButton.disabled = isBusy;
        refreshButton.disabled = isBusy;
        clearButton.disabled = isBusy;
    }

    async function loadConfig() {
        const configs = await ui.getPluginConfig();
        state.config = Array.isArray(configs) && configs.length > 0 ? { ...configs[0] } : {};
        syncFormFromConfig();
        updateStatus();
    }

    async function persistConfig(newValues) {
        const configs = await ui.getPluginConfig();
        const current = Array.isArray(configs) && configs.length > 0 ? configs[0] : {};
        const merged = { ...current, ...newValues };
        await ui.updatePluginConfig([merged]);
        state.config = merged;
        if (typeof ui.savePluginConfig === 'function') {
            await ui.savePluginConfig();
        }
        syncFormFromConfig();
        updateStatus();
    }

    function normalizePersistPayload(tokens = {}, fallback = {}) {
        const strOrEmpty = value => (value === undefined || value === null ? '' : String(value).trim());
        return {
            hardwareId: strOrEmpty(tokens.hardware_id ?? fallback.hardwareId ?? state.config.hardwareId ?? ''),
            accessToken: strOrEmpty(tokens.access_token ?? fallback.accessToken ?? ''),
            refreshToken: strOrEmpty(tokens.refresh_token ?? fallback.refreshToken ?? state.config.refreshToken ?? ''),
            tokenExpiresAt: tokens.expires_at ?? null,
            accountId: tokens.account_id ?? null,
            clientId: tokens.client_id ?? null,
            region: tokens.region ?? null,
            tokenScope: strOrEmpty(tokens.scope ?? state.config.tokenScope ?? ''),
            tokenType: strOrEmpty(tokens.token_type ?? state.config.tokenType ?? ''),
            sessionId: strOrEmpty(tokens.session_id ?? state.config.sessionId ?? ''),
            oauthClientId: strOrEmpty(tokens.oauth_client_id ?? state.config.oauthClientId ?? ''),
            tokenHeaders: tokens.headers
                ? { ...tokens.headers }
                : (state.config.tokenHeaders ?? null),
        };
    }

    async function saveTokens() {
        if (state.busy) return;
        setBusy(true);
        try {
            const form = getFormValues();
            const response = await ui.request('/tokens/normalize', {
                accessToken: form.accessToken,
                refreshToken: form.refreshToken,
                hardwareId: form.hardwareId,
                scope: state.config.tokenScope,
                oauthClientId: state.config.oauthClientId,
                tokenHeaders: state.config.tokenHeaders,
                tokenType: state.config.tokenType,
                sessionId: state.config.sessionId,
                accountId: state.config.accountId,
                clientId: state.config.clientId,
                region: state.config.region,
                tokenExpiresAt: state.config.tokenExpiresAt,
            });
            const tokens = response?.tokens || {};
            await persistConfig(normalizePersistPayload(tokens, form));
            toast.success('Blink tokens saved.');
        } catch (err) {
            console.error('Unable to save Blink tokens', err);
            toast.error(err?.message || 'Unable to save Blink tokens.');
        } finally {
            setBusy(false);
        }
    }

    async function refreshTokens() {
        if (state.busy) return;
        const form = getFormValues();
        const refreshToken = form.refreshToken || state.config.refreshToken;
        if (!refreshToken) {
            toast.error('Add a refresh token before attempting to refresh.');
            return;
        }

        setBusy(true);
        try {
            const response = await ui.request('/tokens/refresh', {
                refreshToken,
                hardwareId: form.hardwareId || state.config.hardwareId,
                scope: state.config.tokenScope,
                clientId: state.config.oauthClientId,
            });
            const tokens = response?.tokens || {};
            tokens.headers = response?.headers || tokens.headers;
            await persistConfig(normalizePersistPayload(tokens, { refreshToken, hardwareId: form.hardwareId }));
            toast.success('Blink tokens refreshed successfully.');
        } catch (err) {
            console.error('Blink token refresh failed', err);
            toast.error(err?.message || 'Blink token refresh failed.');
        } finally {
            setBusy(false);
        }
    }

    async function clearTokens() {
        if (state.busy) return;
        setBusy(true);
        try {
            await persistConfig({
                accessToken: '',
                refreshToken: '',
                tokenExpiresAt: null,
                accountId: null,
                clientId: null,
                region: null,
                tokenScope: '',
                tokenType: '',
                sessionId: '',
                tokenHeaders: null,
                hardwareId: state.config.hardwareId || '',
                oauthClientId: '',
            });
            toast.success('Blink tokens cleared.');
        } catch (err) {
            console.error('Unable to clear Blink tokens', err);
            toast.error(err?.message || 'Unable to clear Blink tokens.');
        } finally {
            setBusy(false);
        }
    }

    saveButton.addEventListener('click', () => saveTokens());
    refreshButton.addEventListener('click', () => refreshTokens());
    clearButton.addEventListener('click', () => clearTokens());

    ui.addEventListener('config-changed', async () => {
        await loadConfig();
    });

    loadConfig();
})();
