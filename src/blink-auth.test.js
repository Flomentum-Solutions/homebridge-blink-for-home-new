const fs = require('fs');
const os = require('os');
const path = require('path');

const { setLogger } = require('./log');
const { Blink } = require('./blink');
const BlinkAPI = require('./blink-api');

const logger = { log: () => {}, error: () => {} };
setLogger(logger, false, false);

describe('Blink OAuth persistence', () => {
    let tempDir;

    beforeEach(() => {
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'blink-oauth-'));
    });

    afterEach(() => {
        jest.restoreAllMocks();
        fs.rmSync(tempDir, { recursive: true, force: true });
    });

    test('writes password grant tokens to cache', async () => {
        const cachePath = path.join(tempDir, 'cache.json');

        const passwordGrantSpy = jest
            .spyOn(BlinkAPI.prototype, 'passwordGrant')
            .mockImplementation(async function () {
                return {
                    access_token: 'token-1',
                    refresh_token: 'refresh-1',
                    expires_in: 3600,
                    account: {
                        account_id: 111,
                        client_id: 222,
                        tier: 'u001',
                        client_verification_required: false,
                    },
                    allow_pin_resend_seconds: 60,
                };
            });
        const refreshGrantSpy = jest
            .spyOn(BlinkAPI.prototype, 'refreshGrant')
            .mockImplementation(async () => {
                throw new Error('refresh should not be used');
            });
        jest.spyOn(BlinkAPI.prototype, 'get').mockResolvedValue({ tier: 'u001' });

        const blink = new Blink(
            'A5BF5C52-56F3-4ADB-A7C2-A70619552084',
            { email: 'user@example.com', password: 'password1' },
            undefined,
            undefined,
            undefined,
            cachePath
        );

        await blink.authenticate();

        expect(passwordGrantSpy).toHaveBeenCalledTimes(1);
        expect(refreshGrantSpy).not.toHaveBeenCalled();

        const stored = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        expect(stored.access_token).toBe('token-1');
        expect(stored.refresh_token).toBe('refresh-1');
        expect(stored.account_id).toBe(111);
        expect(stored.client_id).toBe(222);
        expect(stored.region).toBe('u001');
        expect(stored.expires_at).toBeGreaterThan(Date.now());
    });

    test('falls back to legacy login when oauth endpoint is missing', async () => {
        const cachePath = path.join(tempDir, 'cache.json');

        const postMock = jest
            .spyOn(BlinkAPI.prototype, 'post')
            .mockImplementation(async function (path, body) {
                if (path === '/oauth/token') {
                    return '<h1>Not Found</h1>';
                }
                if (path === '/api/v5/account/login') {
                    expect(body).toMatchObject({
                        email: 'user@example.com',
                        password: 'password1',
                        client_name: 'iPhone',
                        client_type: 'ios',
                        device_identifier: 'iPhone17,1',
                        unique_id: 'A5BF5C52-56F3-4ADB-A7C2-A70619552084',
                    });
                    return {
                        auth: { token: 'legacy-token' },
                        account: {
                            account_id: 555,
                            client_id: 777,
                            tier: 'u002',
                        },
                    };
                }
                throw new Error(`Unexpected path ${path}`);
            });

        jest.spyOn(BlinkAPI.prototype, 'get').mockResolvedValue({ tier: 'u002' });

        const blink = new Blink(
            'A5BF5C52-56F3-4ADB-A7C2-A70619552084',
            { email: 'user@example.com', password: 'password1' },
            undefined,
            undefined,
            undefined,
            cachePath
        );

        await blink.authenticate();

        expect(postMock).toHaveBeenCalledTimes(2);
        expect(postMock.mock.calls[1][0]).toBe('/api/v5/account/login');

        const stored = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        expect(stored.access_token).toBe('legacy-token');
        expect(stored.refresh_token).toBeNull();
        expect(stored.account_id).toBe(555);
        expect(stored.client_id).toBe(777);
        expect(stored.region).toBe('u002');
        expect(stored.expires_at).toBe(0);
    });

    test('refreshes expired bundle automatically', async () => {
        const cachePath = path.join(tempDir, 'cache.json');
        const bundle = {
            access_token: 'token-old',
            refresh_token: 'refresh-old',
            expires_at: Date.now() - 1000,
            account_id: 333,
            client_id: 444,
            region: 'u010',
        };
        fs.writeFileSync(cachePath, JSON.stringify(bundle));

        const refreshGrantSpy = jest
            .spyOn(BlinkAPI.prototype, 'refreshGrant')
            .mockImplementation(async () => ({
                access_token: 'token-new',
                refresh_token: 'refresh-new',
                expires_in: 5400,
            }));
        const passwordGrantSpy = jest
            .spyOn(BlinkAPI.prototype, 'passwordGrant')
            .mockImplementation(async () => ({
                access_token: 'token-password',
                refresh_token: 'refresh-password',
                expires_in: 5400,
                account: {
                    account_id: 333,
                    client_id: 444,
                    tier: 'u010',
                },
            }));
        jest.spyOn(BlinkAPI.prototype, 'get').mockResolvedValue({ tier: 'u010' });

        const blink = new Blink(
            'A5BF5C52-56F3-4ADB-A7C2-A70619552084',
            { email: 'user@example.com', password: 'password1' },
            undefined,
            undefined,
            undefined,
            cachePath
        );

        await blink.authenticate();

        expect(refreshGrantSpy).toHaveBeenCalledTimes(1);
        expect(passwordGrantSpy).not.toHaveBeenCalled();

        const stored = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        expect(stored.access_token).toBe('token-new');
        expect(stored.refresh_token).toBe('refresh-new');
        expect(stored.account_id).toBe(333);
        expect(stored.client_id).toBe(444);
        expect(stored.region).toBe('u010');
        expect(stored.expires_at).toBeGreaterThan(Date.now());
    });
});
