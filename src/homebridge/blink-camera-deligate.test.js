const {describe, expect, test, beforeEach, jest} = require('@jest/globals');
const {EventEmitter} = require('events');
const {HomebridgeAPI} = require('homebridge/lib/api');
const {setLogger} = require('../log');

jest.mock('child_process', () => ({
    spawn: jest.fn(),
}));
jest.mock('@homebridge/camera-utils', () => ({
    getDefaultIpAddress: jest.fn().mockResolvedValue('127.0.0.1'),
    reservePorts: jest.fn().mockResolvedValue([18443]),
}));

const {setHap} = require('./hap');
const homebridge = new HomebridgeAPI();
setHap(homebridge.hap);

// set test logger
const logger = () => {};
logger.log = () => {};
// logger.error = console.error;
logger.error = () => {};
setLogger(logger, false, false);

const BlinkCameraDelegate = require('./blink-camera-deligate');
const {sleep} = require('../utils');
const {BlinkCamera} = require('../blink');

describe('BlinkCameraDelegate', () => {
    const spawnMock = require('child_process').spawn;

    beforeEach(() => {
        spawnMock.mockReset();
    });

    test.concurrent('handleSnapshotRequest(null)', async () => {
        const delegate = new BlinkCameraDelegate();
        const request = {height: 100, width: 100, reason: homebridge.hap.ResourceRequestReason.PERIODIC};
        const cb = (error, val) => {
            expect(val).toStrictEqual(Buffer.from(BlinkCamera.UNSUPPORTED_BYTES));
        };
        await delegate.handleSnapshotRequest(request, cb);
    });
    test.concurrent('handleSnapshotRequest', async () => {
        let refreshThumbnailCalled = 0;
        const cameraDevice = {
            refreshThumbnail: jest.fn().mockImplementation(async () => {
                // little bit of a hack to make sure that we are off the main loop
                await sleep(0);
                refreshThumbnailCalled++;
                throw new Error('should not emit');
            }),
            getThumbnail: jest.fn().mockResolvedValue(Buffer.from([])),
        };
        const delegate = new BlinkCameraDelegate(cameraDevice);
        const request = {height: 100, width: 100, reason: homebridge.hap.ResourceRequestReason.PERIODIC};
        let returnError;
        let returnVal;
        const cb = (error, val) => {
            returnError = error;
            returnVal = val;
        };
        await delegate.handleSnapshotRequest(request, cb);
        expect(returnVal).toStrictEqual(Buffer.from([]));
        expect(returnError).toBeNull();
        expect(cameraDevice.getThumbnail).toHaveBeenCalledTimes(1);
        expect(cameraDevice.refreshThumbnail).toHaveBeenCalledTimes(1);
        expect(refreshThumbnailCalled).toBe(0);

        // this allows us to catch up to the main loop
        await sleep(0);
        expect(refreshThumbnailCalled).toBe(1);
    });
    test.concurrent('prepareStream() negotiates HLS transport', async () => {
        const cameraDevice = {
            name: 'Test Camera',
            getLiveViewURL: jest.fn().mockResolvedValue({
                url: 'https://example.com/playlist.m3u8',
                transport: {
                    type: 'hls',
                    url: 'https://example.com/playlist.m3u8',
                    headers: {Authorization: 'Bearer token'},
                    userAgent: 'ExampleAgent',
                },
                session: {id: 'session'},
                tokens: {},
            }),
        };
        const delegate = new BlinkCameraDelegate(cameraDevice);
        const request = {
            sessionID: 'session-1',
            targetAddress: '10.0.0.2',
            addressVersion: 'ipv4',
            video: {
                port: 5000,
                srtpCryptoSuite: homebridge.hap.SRTPCryptoSuites.AES_CM_128_HMAC_SHA1_80,
                srtp_key: Buffer.alloc(16),
                srtp_salt: Buffer.alloc(14),
            },
        };

        await new Promise((resolve, reject) => {
            delegate.prepareStream(request, (error, response) => {
                if (error) return reject(error);
                expect(response.video.port).toBe(request.video.port);
                resolve();
            }).catch(reject);
        });

        const streamInfo = delegate.proxySessions.get('session-1');
        expect(streamInfo.type).toBe('hls');
        expect(streamInfo.headers.Authorization).toBe('Bearer token');

        const fakeProcess = new EventEmitter();
        fakeProcess.stdout = new EventEmitter();
        fakeProcess.on = fakeProcess.addListener.bind(fakeProcess);
        fakeProcess.kill = jest.fn();
        spawnMock.mockReturnValue(fakeProcess);

        await delegate.startStream('session-1', {
            pt: 99,
            max_bit_rate: 300,
            mtu: 1378,
            width: 1280,
            height: 720,
        }, null);

        expect(spawnMock).toHaveBeenCalledTimes(1);
        const args = spawnMock.mock.calls[0][1];
        const headersIndex = args.indexOf('-headers');
        expect(headersIndex).toBeGreaterThan(-1);
        expect(args[headersIndex + 1]).toContain('Authorization: Bearer token');
        expect(args).toContain('https://example.com/playlist.m3u8');
    });
    test.concurrent('stopStream()', async () => {
        const delegate = new BlinkCameraDelegate();
        await delegate.stopStream(1);

        delegate.proxySessions.set(1, {});
        await delegate.stopStream(1);
        expect(delegate.proxySessions.keys()).not.toContain(1);

        const proxy = {proxyServer: {}};
        delegate.proxySessions.set(1, proxy);
        await delegate.stopStream(1);
        expect(delegate.proxySessions.keys()).not.toContain(1);

        proxy.proxyServer.stop = jest.fn().mockResolvedValue(true);
        delegate.proxySessions.set(1, proxy);
        await delegate.stopStream(1);
        expect(proxy.proxyServer.stop).toHaveBeenCalledTimes(1);
        expect(delegate.proxySessions.keys()).not.toContain(1);

        proxy.proxyServer.stop = jest.fn().mockRejectedValue('ERROR');
        delegate.proxySessions.set(1, proxy);
        await delegate.stopStream(1);
        expect(proxy.proxyServer.stop).toHaveBeenCalledTimes(1);
        expect(delegate.proxySessions.keys()).not.toContain(1);

        // ongoing Ssssions
        delegate.ongoingSessions.set(1, null);
        await delegate.stopStream(1);
        expect(delegate.ongoingSessions.keys()).not.toContain(1);

        const session = {};
        delegate.ongoingSessions.set(1, session);
        await delegate.stopStream(1);
        expect(delegate.ongoingSessions.keys()).not.toContain(1);

        session.kill = jest.fn().mockReturnValue(true);
        delegate.ongoingSessions.set(1, session);
        await delegate.stopStream(1);
        expect(session.kill).toHaveBeenCalledTimes(1);
        expect(delegate.ongoingSessions.keys()).not.toContain(1);

        session.kill = jest.fn().mockImplementation(() => {
            throw new Error('ERROR');
        });
        delegate.ongoingSessions.set(1, session);
        await delegate.stopStream(1);
        expect(session.kill).toHaveBeenCalledTimes(1);
        expect(delegate.ongoingSessions.keys()).not.toContain(1);
    });
});
