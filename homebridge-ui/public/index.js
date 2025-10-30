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
        sessionId: null,
        polling: null,
    };

    const statusEl = document.getElementById('status');
    const hardwareEl = document.getElementById('detail-hardware');
    const expiryEl = document.getElementById('detail-expiry');
    const accountEl = document.getElementById('detail-account');
    const regionEl = document.getElementById('detail-region');
    const signInButton = document.getElementById('sign-in');
    const resetButton = document.getElementById('reset');

    function formatExpiry(timestamp) {
        if (!timestamp) return '—';
        const date = new Date(Number(timestamp));
        if (Number.isNaN(date.getTime())) return '—';
        return `${date.toLocaleString()} (${Math.max(0, Math.round((timestamp - Date.now()) / 60000))} min)`;
    }

    function updateStatus(config) {
        const status = config.signInStatus || 'Not signed in';
        statusEl.textContent = status;
        hardwareEl.textContent = config.hardwareId || '—';
        expiryEl.textContent = config.tokenExpiresAt ? formatExpiry(config.tokenExpiresAt) : '—';
        if (config.accountId) {
            accountEl.textContent = `Account ${config.accountId}`;
        }
        else if (config.username) {
            accountEl.textContent = config.username;
        }
        else {
            accountEl.textContent = '—';
        }
        regionEl.textContent = config.region || '—';
        const isBusy = state.sessionId !== null;
        signInButton.disabled = isBusy;
        resetButton.disabled = isBusy;
    }

    async function loadConfig() {
        const configs = await ui.getPluginConfig();
        if (Array.isArray(configs) && configs.length > 0) {
            state.config = { ...configs[0] };
        }
        else {
            state.config = {};
        }
        updateStatus(state.config);
    }

    async function persistConfig(newValues) {
        const configs = await ui.getPluginConfig();
        const current = Array.isArray(configs) && configs.length > 0 ? configs[0] : {};
        const merged = { ...current, ...newValues };
        await ui.updatePluginConfig([merged]);
        state.config = merged;
        updateStatus(state.config);
        if (typeof ui.savePluginConfig === 'function') {
            await ui.savePluginConfig();
        }
    }

    function stopPolling() {
        if (state.polling) {
            clearTimeout(state.polling);
            state.polling = null;
        }
    }

    async function pollSession() {
        if (!state.sessionId) return;
        try {
            const response = await ui.request('/oauth/status', { sessionId: state.sessionId });
            switch (response?.status) {
                case 'pending':
                    state.polling = setTimeout(pollSession, 1500);
                    break;
                case 'complete':
                    stopPolling();
                    state.sessionId = null;
                    await persistConfig({
                        hardwareId: response.hardwareId || state.config.hardwareId,
                        accessToken: response.tokens?.access_token || null,
                        refreshToken: response.tokens?.refresh_token || null,
                        tokenExpiresAt: response.tokens?.expires_at || null,
                        accountId: response.tokens?.account_id || null,
                        clientId: response.tokens?.client_id || null,
                        region: response.tokens?.region || null,
                        signInStatus: 'Signed in',
                    });
                    toast.success('Blink account linked successfully.');
                    break;
                case 'error':
                    stopPolling();
                    state.sessionId = null;
                    await persistConfig({
                        signInStatus: 'Error',
                    });
                    toast.error(response.message || 'Blink OAuth flow failed.');
                    break;
                default:
                    stopPolling();
                    state.sessionId = null;
                    break;
            }
        }
        catch (err) {
            console.error('Status polling failed', err);
            stopPolling();
            state.sessionId = null;
            toast.error(err?.message || 'Unable to monitor Blink OAuth flow.');
            await persistConfig({
                signInStatus: 'Error',
            });
        }
    }

    function defaultHardwareId() {
        if (state.config.hardwareId) return state.config.hardwareId;
        if (window.crypto?.randomUUID) return window.crypto.randomUUID();
        const template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
        return template.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    async function beginSignIn() {
        stopPolling();
        signInButton.disabled = true;
        resetButton.disabled = true;
        try {
            const payload = {
                redirectPort: state.config.redirectPort || 52888,
                clientId: state.config.oauthClientId || 'ios',
                scope: state.config.oauthScope || 'client offline_access',
                hardwareId: state.config.hardwareId || defaultHardwareId(),
                redirectHost: window.location.hostname,
                redirectProtocol: window.location.protocol,
            };
            const response = await ui.request('/oauth/start', payload);
            if (response?.error) {
                throw new Error(response.error);
            }
            if (response?.sessionId) {
                state.sessionId = response.sessionId;
                if (response.hardwareId && response.hardwareId !== state.config.hardwareId) {
                    state.config.hardwareId = response.hardwareId;
                }
                await persistConfig({
                    hardwareId: state.config.hardwareId,
                    signInStatus: 'Not signed in',
                });
                if (response.authUrl) {
                    window.open(response.authUrl, '_blank', 'noopener');
                }
                state.polling = setTimeout(pollSession, 1500);
            }
            else {
                throw new Error('Unable to start Blink OAuth session.');
            }
        }
        catch (err) {
            console.error('Unable to start Blink OAuth flow', err);
            toast.error(err?.message || 'Unable to start Blink OAuth flow.');
            await persistConfig({
                signInStatus: 'Error',
            });
        }
        finally {
            signInButton.disabled = state.sessionId !== null;
            resetButton.disabled = state.sessionId !== null;
        }
    }

    async function resetLink() {
        stopPolling();
        state.sessionId = null;
        await persistConfig({
            accessToken: null,
            refreshToken: null,
            tokenExpiresAt: null,
            accountId: null,
            clientId: null,
            region: null,
            signInStatus: 'Not signed in',
        });
        toast.success('Blink OAuth tokens cleared.');
    }

    signInButton.addEventListener('click', beginSignIn);
    resetButton.addEventListener('click', resetLink);

    ui.addEventListener('config-changed', async () => {
        await loadConfig();
    });

    loadConfig();
})();
