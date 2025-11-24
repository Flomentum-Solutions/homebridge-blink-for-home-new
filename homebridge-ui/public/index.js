(() => {
    const ui = window.homebridge;
    const toast = {
        success(message) {
            if (ui.toast?.success) ui.toast.success(message);
            else console.info(message);
        },
        info(message) {
            if (ui.toast?.info) ui.toast.info(message);
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
        awaitingPin: false,
    };

    const statusEl = document.getElementById('status');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const pinInput = document.getElementById('pin');
    const pinRow = document.getElementById('pin-row');
    const pinHelp = document.getElementById('pin-help');
    const otpInput = document.getElementById('otp');
    const accessInput = document.getElementById('access-token');
    const refreshInput = document.getElementById('refresh-token');
    const hardwareInput = document.getElementById('hardware-id');
    const nameInput = document.getElementById('config-name');
    const ffmpegInput = document.getElementById('ffmpeg-path');
    const loggingSelect = document.getElementById('logging');
    const startupDiagnosticInput = document.getElementById('enable-startup-diagnostic');
    const hideAlarmInput = document.getElementById('hide-alarm');
    const hideManualArmInput = document.getElementById('hide-manual-arm-switch');
    const hideTempInput = document.getElementById('hide-temperature-sensor');
    const hideEnabledInput = document.getElementById('hide-enabled-switch');
    const hidePrivacyInput = document.getElementById('hide-privacy-switch');
    const liveViewInput = document.getElementById('enable-liveview');
    const disableThumbnailInput = document.getElementById('disable-thumbnail-refresh');
    const motionPollingInput = document.getElementById('camera-motion-polling-seconds');
    const statusPollingInput = document.getElementById('camera-status-polling-seconds');
    const thumbnailRefreshInput = document.getElementById('camera-thumbnail-refresh-seconds');
    const expiryEl = document.getElementById('detail-expiry');
    const hardwareSummaryEl = document.getElementById('detail-hardware');
    const accountEl = document.getElementById('detail-account');
    const clientEl = document.getElementById('detail-client');
    const regionEl = document.getElementById('detail-region');
    const scopeEl = document.getElementById('detail-scope');
    const typeEl = document.getElementById('detail-type');
    const sessionEl = document.getElementById('detail-session');
    const oauthClientEl = document.getElementById('detail-oauth-client');
    const headersContainer = document.getElementById('detail-headers');
    const headersToggle = document.getElementById('detail-headers-toggle');
    const headersDump = document.getElementById('detail-headers-dump');
    const saveTokensButton = document.getElementById('save-tokens');
    const refreshButton = document.getElementById('refresh-tokens');
    const clearTokensButton = document.getElementById('clear-tokens');
    const saveCredentialsButton = document.getElementById('save-credentials');
    const loginButton = document.getElementById('login-credentials');
    const clearCredentialsButton = document.getElementById('clear-credentials');
    const saveSettingsButton = document.getElementById('save-settings');
    const defaultPinMessage = pinHelp?.textContent || 'Enter the 6-digit PIN Blink sends to you.';

    function formatExpiry(timestamp) {
        if (!timestamp) return '—';
        const date = new Date(Number(timestamp));
        if (Number.isNaN(date.getTime())) return '—';
        const minutes = Math.max(0, Math.round((timestamp - Date.now()) / 60000));
        return `${date.toLocaleString()} (${minutes} min)`;
    }

    function summariseHeaders(headers) {
        if (!headers || typeof headers !== 'object') return { label: '—', entries: [], json: '' };
        const entries = Object.entries(headers)
            .filter(([, value]) => value !== undefined && value !== null && value !== '');
        if (!entries.length) return { label: '—', entries: [], json: '' };
        const label = `${entries.length} header${entries.length === 1 ? '' : 's'}`;
        const payload = Object.fromEntries(entries);
        const json = JSON.stringify(payload, null, 2);
        return { label, entries, json };
    }

    function togglePinPrompt(show, options = {}) {
        const { focus = false, message = defaultPinMessage } = options || {};
        if (!pinRow) return;
        pinRow.classList.toggle('hidden', !show);
        if (pinHelp) pinHelp.textContent = message || defaultPinMessage;
        if (show) {
            state.awaitingPin = true;
            if (pinInput) {
                pinInput.value = '';
                if (focus) pinInput.focus();
            }
        } else {
            state.awaitingPin = false;
        }
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
        const clientIdHeader = state.config.tokenHeaders?.['client-id']
            ?? state.config.tokenHeaders?.['x-client-id']
            ?? state.config.tokenHeaders?.['client_id'];
        const effectiveClientId = state.config.clientId ?? clientIdHeader ?? '';
        clientEl.textContent = effectiveClientId ? `Client ${effectiveClientId}` : '—';
        regionEl.textContent = state.config.region || '—';
        scopeEl.textContent = state.config.tokenScope || '—';
        typeEl.textContent = state.config.tokenType || '—';
        oauthClientEl.textContent = state.config.oauthClientId || '—';
        const sessionIdHeader = state.config.tokenHeaders?.['session-id']
            ?? state.config.tokenHeaders?.['x-session-id']
            ?? state.config.tokenHeaders?.['session_id'];
        const effectiveSessionId = state.config.sessionId || sessionIdHeader || '';
        sessionEl.textContent = effectiveSessionId || '—';
        if (headersToggle && headersDump && headersContainer) {
            const headerSummary = summariseHeaders(state.config.tokenHeaders);
            headersToggle.textContent = headerSummary.label;
            headersToggle.disabled = headerSummary.entries.length === 0;
            headersToggle.classList.toggle('disabled', headerSummary.entries.length === 0);
            if (headerSummary.entries.length === 0) {
                headersDump.classList.remove('open');
                headersDump.textContent = '';
                headersToggle.setAttribute('aria-expanded', 'false');
                headersContainer.classList.remove('has-data');
            } else {
                headersDump.textContent = headerSummary.json;
                headersToggle.setAttribute('aria-expanded', headersDump.classList.contains('open') ? 'true' : 'false');
                headersContainer.classList.add('has-data');
            }
        }
    }

    function syncFormFromConfig() {
        usernameInput.value = state.config.username || state.config.email || '';
        passwordInput.value = state.config.password || '';
        pinInput.value = state.config.pin || '';
        otpInput.value = state.config.otp || state.config.twoFactorCode || state.config.twoFactorToken || '';
        hardwareInput.value = state.config.hardwareId || '';
        accessInput.value = state.config.accessToken || '';
        refreshInput.value = state.config.refreshToken || '';
        if (nameInput) nameInput.value = state.config.name || '';
        if (ffmpegInput) ffmpegInput.value = state.config.ffmpegPath || '';
        if (loggingSelect) loggingSelect.value = state.config.logging || '';
        if (startupDiagnosticInput) startupDiagnosticInput.checked = Boolean(state.config['enable-startup-diagnostic']);
        if (hideAlarmInput) hideAlarmInput.checked = Boolean(state.config['hide-alarm']);
        if (hideManualArmInput) hideManualArmInput.checked = Boolean(state.config['hide-manual-arm-switch']);
        if (hideTempInput) hideTempInput.checked = Boolean(state.config['hide-temperature-sensor']);
        if (hideEnabledInput) hideEnabledInput.checked = Boolean(state.config['hide-enabled-switch']);
        if (hidePrivacyInput) hidePrivacyInput.checked = Boolean(state.config['hide-privacy-switch']);
        if (liveViewInput) liveViewInput.checked = Boolean(state.config['enable-liveview']);
        if (disableThumbnailInput) disableThumbnailInput.checked = Boolean(state.config['disable-thumbnail-refresh']);
        if (motionPollingInput) motionPollingInput.value = state.config['camera-motion-polling-seconds'] ?? '';
        if (statusPollingInput) statusPollingInput.value = state.config['camera-status-polling-seconds'] ?? '';
        if (thumbnailRefreshInput) thumbnailRefreshInput.value = state.config['camera-thumbnail-refresh-seconds'] ?? '';

        const shouldShowPin = state.awaitingPin || (!state.config.accessToken && Boolean(state.config.pin));
        togglePinPrompt(shouldShowPin, { focus: false });
    }

    function getAuthFormValues() {
        return {
            username: usernameInput.value.trim(),
            password: passwordInput.value,
            pin: pinInput.value.trim(),
            otp: otpInput.value.trim(),
            hardwareId: hardwareInput.value.trim(),
            accessToken: accessInput.value.trim(),
            refreshToken: refreshInput.value.trim(),
        };
    }

    function toNumberOrEmpty(inputEl) {
        if (!inputEl) return '';
        const raw = inputEl.value.trim();
        if (raw === '') return '';
        const parsed = Number(raw);
        return Number.isNaN(parsed) ? '' : parsed;
    }

    function getSettingsValues() {
        return {
            name: nameInput?.value?.trim() || '',
            ffmpegPath: ffmpegInput?.value?.trim() || '',
            otp: otpInput.value.trim(),
            logging: loggingSelect?.value || '',
            'enable-startup-diagnostic': Boolean(startupDiagnosticInput?.checked),
            'hide-alarm': Boolean(hideAlarmInput?.checked),
            'hide-manual-arm-switch': Boolean(hideManualArmInput?.checked),
            'hide-temperature-sensor': Boolean(hideTempInput?.checked),
            'hide-enabled-switch': Boolean(hideEnabledInput?.checked),
            'hide-privacy-switch': Boolean(hidePrivacyInput?.checked),
            'enable-liveview': Boolean(liveViewInput?.checked),
            'disable-thumbnail-refresh': Boolean(disableThumbnailInput?.checked),
            'camera-motion-polling-seconds': toNumberOrEmpty(motionPollingInput),
            'camera-status-polling-seconds': toNumberOrEmpty(statusPollingInput),
            'camera-thumbnail-refresh-seconds': toNumberOrEmpty(thumbnailRefreshInput),
        };
    }

    function setBusy(isBusy) {
        state.busy = isBusy;
        saveTokensButton.disabled = isBusy;
        refreshButton.disabled = isBusy;
        clearTokensButton.disabled = isBusy;
        saveCredentialsButton.disabled = isBusy;
        loginButton.disabled = isBusy;
        clearCredentialsButton.disabled = isBusy;
        if (saveSettingsButton) saveSettingsButton.disabled = isBusy;
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

    async function saveSettings() {
        if (state.busy) return;
        const settings = getSettingsValues();
        if (!settings.name) {
            toast.error('Enter a platform name before saving settings.');
            if (nameInput) nameInput.focus();
            return;
        }
        setBusy(true);
        try {
            await persistConfig(settings);
            toast.success('Blink settings saved.');
        } catch (err) {
            console.error('Unable to save Blink settings', err);
            toast.error(err?.message || 'Unable to save Blink settings.');
        } finally {
            setBusy(false);
        }
    }

    function normalizePersistPayload(tokens = {}, fallback = {}) {
        const strOrEmpty = value => (value === undefined || value === null ? '' : String(value).trim());
        const headerSource = tokens.headers ?? fallback.tokenHeaders ?? state.config.tokenHeaders ?? {};
        const headerLookup = key => {
            if (!headerSource || typeof headerSource !== 'object') return undefined;
            const lowered = String(key).toLowerCase();
            for (const [headerKey, value] of Object.entries(headerSource)) {
                if (headerKey.toLowerCase() === lowered) return value;
            }
            return undefined;
        };

        return {
            hardwareId: strOrEmpty(tokens.hardware_id ?? fallback.hardwareId ?? state.config.hardwareId ?? ''),
            accessToken: strOrEmpty(tokens.access_token ?? fallback.accessToken ?? state.config.accessToken ?? ''),
            refreshToken: strOrEmpty(tokens.refresh_token ?? fallback.refreshToken ?? state.config.refreshToken ?? ''),
            tokenExpiresAt: tokens.expires_at ?? fallback.tokenExpiresAt ?? state.config.tokenExpiresAt ?? null,
            accountId: tokens.account_id
                ?? fallback.accountId
                ?? state.config.accountId
                ?? headerLookup('account-id')
                ?? null,
            clientId: tokens.client_id ?? fallback.clientId ?? state.config.clientId ?? headerLookup('client-id') ?? null,
            region: tokens.region ?? fallback.region ?? state.config.region ?? null,
            tokenScope: strOrEmpty(tokens.scope ?? fallback.tokenScope ?? state.config.tokenScope ?? ''),
            tokenType: strOrEmpty(tokens.token_type ?? fallback.tokenType ?? state.config.tokenType ?? ''),
            sessionId: strOrEmpty(
                tokens.session_id
                ?? fallback.sessionId
                ?? state.config.sessionId
                ?? headerLookup('session-id')
                ?? ''
            ),
            oauthClientId: strOrEmpty(tokens.oauth_client_id ?? fallback.oauthClientId ?? state.config.oauthClientId ?? ''),
            tokenHeaders: tokens.headers
                ? { ...tokens.headers }
                : (fallback.tokenHeaders ?? state.config.tokenHeaders ?? null),
        };
    }

    async function saveCredentials() {
        if (state.busy) return;
        const { username, password, pin, otp, hardwareId } = getAuthFormValues();
        if (!username || !password) {
            toast.error('Enter your Blink email and password before saving credentials.');
            return;
        }
        setBusy(true);
        try {
            await persistConfig({ username, password, pin, otp, hardwareId });
            toast.success('Blink credentials saved.');
        } catch (err) {
            console.error('Unable to save Blink credentials', err);
            toast.error(err?.message || 'Unable to save Blink credentials.');
        } finally {
            setBusy(false);
        }
    }

    async function saveTokens() {
        if (state.busy) return;
        setBusy(true);
        try {
            const form = getAuthFormValues();
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
            await persistConfig({
                ...normalizePersistPayload(tokens, form),
                username: form.username || state.config.username || '',
                password: form.password || state.config.password || '',
                pin: form.pin || state.config.pin || '',
                otp: form.otp || state.config.otp || '',
            });
            toast.success('Blink tokens saved.');
        } catch (err) {
            console.error('Unable to save Blink tokens', err);
            toast.error(err?.message || 'Unable to save Blink tokens.');
        } finally {
            setBusy(false);
        }
    }

    async function loginWithCredentials(options = {}) {
        const { autoSubmit = false } = options || {};
        if (state.busy) return;
        const form = getAuthFormValues();
        if (!form.username || !form.password) {
            toast.error('Enter your Blink email and password before logging in.');
            return;
        }
        setBusy(true);
        try {
            const response = await ui.request('/tokens/login', {
                username: form.username,
                password: form.password,
                pin: form.pin,
                otp: form.otp,
                hardwareId: form.hardwareId || state.config.hardwareId,
                refreshToken: form.refreshToken || state.config.refreshToken,
                accessToken: form.accessToken || state.config.accessToken,
                tokenExpiresAt: state.config.tokenExpiresAt,
            });
            if (response?.status === '2fa-required') {
                const infoMessage = response?.message
                    || 'Two-factor verification required. Check your phone for the 6-digit PIN and enter it below.';
                await persistConfig({
                    username: form.username,
                    password: form.password,
                    hardwareId: form.hardwareId || state.config.hardwareId || '',
                    refreshToken: form.refreshToken || state.config.refreshToken || '',
                    accessToken: form.accessToken || state.config.accessToken || '',
                    pin: '',
                });
                toast.info(infoMessage);
                togglePinPrompt(true, { focus: !autoSubmit, message: infoMessage });
                return;
            }
            const tokens = response?.tokens || {};
            await persistConfig({
                ...normalizePersistPayload(tokens, {
                    refreshToken: form.refreshToken || state.config.refreshToken,
                    hardwareId: form.hardwareId || state.config.hardwareId,
                }),
                username: form.username,
                password: form.password,
                pin: '',
                otp: '',
            });
            state.awaitingPin = false;
            togglePinPrompt(false);
            syncFormFromConfig();
            toast.success('Blink login successful. Tokens updated.');
        } catch (err) {
            console.error('Blink login failed', err);
            const message = err?.message || '';
            if (/2fa required|pin sent/i.test(message)) {
                const infoMessage = message || 'Check your phone for the 2FA PIN and enter it below.';
                toast.info(infoMessage);
                togglePinPrompt(true, { focus: !autoSubmit, message: infoMessage });
            } else {
                toast.error(message || 'Blink login failed. Verify your credentials and 2FA inputs.');
            }
        } finally {
            setBusy(false);
        }
    }

    async function refreshTokens() {
        if (state.busy) return;
        const form = getAuthFormValues();
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
            await persistConfig({
                ...normalizePersistPayload(tokens, { refreshToken, hardwareId: form.hardwareId }),
                username: form.username || state.config.username || '',
                password: form.password || state.config.password || '',
                pin: state.config.pin || '',
                otp: state.config.otp || '',
            });
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
                username: state.config.username || '',
                password: state.config.password || '',
                pin: state.config.pin || '',
                otp: state.config.otp || '',
            });
            state.awaitingPin = false;
            togglePinPrompt(false);
            toast.success('Blink tokens cleared.');
        } catch (err) {
            console.error('Unable to clear Blink tokens', err);
            toast.error(err?.message || 'Unable to clear Blink tokens.');
        } finally {
            setBusy(false);
        }
    }

    async function clearCredentials() {
        if (state.busy) return;
        setBusy(true);
        try {
            await persistConfig({
                username: '',
                password: '',
                pin: '',
                otp: '',
            });
            state.awaitingPin = false;
            togglePinPrompt(false);
            syncFormFromConfig();
            toast.success('Blink credentials cleared.');
        } catch (err) {
            console.error('Unable to clear Blink credentials', err);
            toast.error(err?.message || 'Unable to clear Blink credentials.');
        } finally {
            setBusy(false);
        }
    }

    if (headersToggle && headersDump) {
        headersToggle.addEventListener('click', () => {
            if (headersToggle.disabled) return;
            const open = headersDump.classList.toggle('open');
            headersToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
    }

    if (saveCredentialsButton) saveCredentialsButton.addEventListener('click', () => saveCredentials());
    if (loginButton) loginButton.addEventListener('click', () => loginWithCredentials());
    if (clearCredentialsButton) clearCredentialsButton.addEventListener('click', () => clearCredentials());
    if (saveTokensButton) saveTokensButton.addEventListener('click', () => saveTokens());
    if (refreshButton) refreshButton.addEventListener('click', () => refreshTokens());
    if (clearTokensButton) clearTokensButton.addEventListener('click', () => clearTokens());
    if (saveSettingsButton) saveSettingsButton.addEventListener('click', () => saveSettings());
    if (pinInput) {
        pinInput.addEventListener('input', () => {
            const pinValue = pinInput.value.trim();
            if (!state.awaitingPin || state.busy) return;
            if (/^\d{6}$/.test(pinValue)) {
                loginWithCredentials({ autoSubmit: true });
            }
        });
    }

    ui.addEventListener('config-changed', async () => {
        await loadConfig();
    });

    loadConfig();
})();
