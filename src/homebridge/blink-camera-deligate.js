// import ip from "ip";
const {spawn} = require('child_process');
const {log} = require('../log');
const {hap} = require('./hap');
const {BlinkCamera} = require('../blink');
const {CameraController, SRTPCryptoSuites, StreamRequestTypes, ResourceRequestReason} = hap;

const {
    // doesFfmpegSupportCodec,
    // encodeSrtpOptions,
    getDefaultIpAddress,
    // ReturnAudioTranscoder,
    // RtpSplitter,
    reservePorts,
    // releasePorts,
} = require('@homebridge/camera-utils');
const pathToFfmpeg = require('ffmpeg-for-homebridge');

const {Http2TLSTunnel, formatFfmpegHeaders} = require('../proxy');
// class SessionInfo {
//     address: string, // address of the HAP controller
//
//     videoPort: number,
//     videoCryptoSuite: SRTPCryptoSuites, // should be saved if multiple suites are supported
//     videoSRTP: Buffer, // key and salt concatenated
//     videoSSRC: number, // rtp synchronisation source
//
//     /* Won't be save as audio is not supported by this example
//     audioPort: number,
//     audioCryptoSuite: SRTPCryptoSuites,
//     audioSRTP: Buffer,
//     audioSSRC: number,
//      */
// }

// const AudioStreamingCodecType = {
//     PCMU: 'PCMU',
//     PCMA: 'PCMA',
//     AAC_ELD: 'AAC-eld',
//     OPUS: 'OPUS',
//     MSBC: 'mSBC',
//     AMR: 'AMR',
//     AMR_WB: 'AMR-WB',
// };
// const AudioStreamingSamplerate = {
//     KHZ_8: 8,
//     KHZ_16: 16,
//     KHZ_24: 24,
// };

// const FFMPEGH264ProfileNames = [
//     'baseline',
//     'main',
//     'high',
// ];
// const FFMPEGH264LevelNames = [
//     '3.1',
//     '3.2',
//     '4.0',
// ];

const DEFAULT_IMAGE_URL =`${__dirname}/../offline.png`;
class BlinkCameraDelegate {
    constructor(blinkCamera) {
        this.blinkCamera = blinkCamera;

        // keep track of sessions
        this.pendingSessions = new Map();
        this.proxySessions = new Map();
        this.ongoingSessions = new Map();
    }

    async handleSnapshotRequest(request, callback) {
        log.debug(`${this.blinkCamera?.name} - handleSnapshotRequest()`);

        // we return the current thumbnail faster and async refresh to avoid long delays
        const bytes = await this.blinkCamera?.getThumbnail(request.reason === ResourceRequestReason.EVENT);
        this.blinkCamera?.refreshThumbnail().catch(e => log.error(`${this.blinkCamera?.name} - ERROR:`, e));
        return callback(null, Buffer.from(bytes || BlinkCamera.UNSUPPORTED_BYTES));
    }

    // called when iOS request rtp setup
    async prepareStream(request, callback) {
        log.debug(`${this.blinkCamera.name} - prepareStream()`, request);

        const videoSSRC = CameraController.generateSynchronisationSource();
        const sessionInfo = {
            address: request.targetAddress,
            videoPort: request.video?.port,
            videoCryptoSuite: request.video?.srtpCryptoSuite,
            videoSRTP: Buffer.concat([request.video?.srtp_key, request.video?.srtp_salt]),
            videoSSRC: videoSSRC,
        };
        const response = {
            // SOMEDAY: remove address as it is not needed after homebridge 1.1.3
            address: await getDefaultIpAddress(request.addressVersion === 'ipv6'),
            video: {
                port: request.video?.port,
                ssrc: videoSSRC,

                srtp_key: request.video?.srtp_key,
                srtp_salt: request.video?.srtp_salt,
            },
        };

        this.pendingSessions.set(request.sessionID, sessionInfo);
        this.proxySessions.set(request.sessionID, {type: 'image', path: DEFAULT_IMAGE_URL});

        const liveView = await this.blinkCamera.getLiveViewURL();
        const liveViewURL = liveView?.url || liveView?.legacy?.url;
        log.info(`${this.blinkCamera?.name} - LiveView: ${liveViewURL || 'unavailable'}`);

        const sessionMeta = {
            session: liveView?.session,
            tokens: liveView?.tokens,
            transport: liveView?.transport,
        };

        this.pendingSessions.set(request.sessionID, {...sessionInfo, ...sessionMeta});

        // TODO: this is messy as hell - massive cleanup necessary
        const rtspRegex = /([a-z]+):\/\/([^:/]+)(?::[0-9]+)?(\/.*)/;
        if (liveView?.transport?.type?.startsWith('rtsp') && liveView?.transport?.url && rtspRegex.test(liveView.transport.url)) {
            const [, protocol, host, path] = rtspRegex.exec(liveView.transport.url);
            const [listenPort] = await reservePorts({count: 1});
            const proxyServer = await this.createTLSTunnel(listenPort, host, protocol);
            const rtspProxy = {type: 'rtsp', protocol, host, path, listenPort, proxyServer};
            this.proxySessions.set(request.sessionID, {...rtspProxy, headers: liveView.transport.headers});
        }
        else if (liveViewURL?.startsWith('rtsp') && rtspRegex.test(liveViewURL)) {
            const [, protocol, host, path] = rtspRegex.exec(liveViewURL);
            const [listenPort] = await reservePorts({count: 1});
            const proxyServer = await this.createTLSTunnel(listenPort, host, protocol);
            const rtspProxy = {type: 'rtsp', protocol, host, path, listenPort, proxyServer};
            this.proxySessions.set(request.sessionID, rtspProxy);
        }
        else if (liveViewURL?.startsWith('immis')) {
            // TODO: decode the proproietary rtsp stream
            // TODO: send screenshots instead
        }
        else if (liveView?.transport?.url && /^https?:/i.test(liveView.transport.url)) {
            this.proxySessions.set(request.sessionID, {
                type: 'hls',
                url: liveView.transport.url,
                headers: liveView.transport.headers || liveView.headers,
                userAgent: liveView.transport.userAgent || 'Immedia WalnutPlayer',
            });
        }
        else if (liveViewURL) {
            this.proxySessions.set(request.sessionID, {type: 'image', path: liveViewURL});
        }
        callback(null, response);
    }

    // called when iOS device asks stream to start/stop/reconfigure
    async handleStreamRequest(request, callback) {
        log.debug(`${this.blinkCamera?.name} - handleStreamRequest()`, request);

        if (request.type === StreamRequestTypes.START) {
            await this.startStream(request.sessionID, request.video, request.audio);
        }
        else if (request.type === StreamRequestTypes.STOP) {
            await this.stopStream(request.sessionID);
        }
        else if (request.type === StreamRequestTypes.RECONFIGURE) {
            // not supported
            log.debug(`${this.blinkCamera?.name} - LiveView RECONFIGURE (unsupported): ${JSON.stringify(request.video)}`);
        }
        callback();
    }

    async startStream(sessionID, video, audio) {
        const sessionInfo = this.pendingSessions.get(sessionID);
        if (!sessionInfo) return;

        const streamInfo = this.proxySessions.get(sessionID) || {};

        // const profile = FFMPEGH264ProfileNames[video.profile];
        // const level = FFMPEGH264LevelNames[video.level];

        const payloadType = video.pt;
        const maxBitrate = video.max_bit_rate;
        // const rtcpInterval = video.rtcp_interval; // usually 0.5

        const address = sessionInfo.address;
        const videoPort = sessionInfo.videoPort;
        const videoSRTP = sessionInfo.videoSRTP.toString('base64');

        // eslint-disable-next-line max-len
        log.info(`${this.blinkCamera.name} - LiveView START (${video.width}x${video.height}, ${video.fps} fps, ${maxBitrate} kbps, ${video.mtu} mtu)...`);
        const videoffmpegCommand = [];

        log.debug(`${this.blinkCamera.name} - PROXY`, streamInfo);
        if (streamInfo.type === 'rtsp' && streamInfo.proxyServer) {
            // push as individual args (avoid later splitting which breaks values with spaces)
            videoffmpegCommand.push(
                '-hide_banner', '-loglevel', 'warning',
                '-i', `rtsp://localhost:${streamInfo.listenPort}${streamInfo.path}`,
                // `-map 0:a`,
                // `-ac 1 -ar 16k`, // audio channel: 1, audio sample rate: 16k
                // `-b:a 24k -bufsize 24k`,
                // `-flags +global_header`,
                // '-acodec copy',
                '-map', '0:0',
                '-vcodec', 'copy',
                // `-c:v libx264 -pix_fmt yuv420p -r ${video.fps}`,
                // `-an -sn -dn`, //disable audio, subtitles, data
                // `-b:v ${maxBitrate}k -bufsize ${2 * maxBitrate}k -maxrate ${maxBitrate}k`,
                // `-profile:v ${profile} -level:v ${level}`,
                '-user-agent', 'Immedia%20WalnutPlayer' // %20 is a special case, we will turn back to a space later
            );
        }
        else if (streamInfo.type === 'hls' && streamInfo.url) {
            const headerString = formatFfmpegHeaders(streamInfo.headers);
            // push as individual args; keep header/user-agent values intact (may contain spaces)
            videoffmpegCommand.push('-hide_banner', '-loglevel', 'warning');
            if (headerString) {
                videoffmpegCommand.push('-headers', headerString);
            }
            videoffmpegCommand.push('-user_agent', streamInfo.userAgent || 'Immedia WalnutPlayer');
            videoffmpegCommand.push('-i', streamInfo.url);
            videoffmpegCommand.push('-map', '0:0');
            videoffmpegCommand.push('-vcodec', 'copy');
        }
        else {
            const stillPath = streamInfo.path || DEFAULT_IMAGE_URL;
            videoffmpegCommand.push(
                '-hide_banner', '-loglevel', 'warning',
                '-loop', '1', '-framerate', '1', '-re', // loop single frame, slow down encode
                '-f', 'image2', '-i', `${stillPath}`,
                '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', // h264 with 3.0 profile
                '-profile:v', 'baseline', '-s', `${video.width}x${video.height}`,
                '-g', '300', '-r', '10', // fps=10 (not ${video.fps}) and iframe every 300 fps
                '-an', '-sn', '-dn', // disable audio, subtitles, data
                '-b:v', `${maxBitrate}k`, '-bufsize', `${2 * maxBitrate}k`, '-maxrate', `${maxBitrate}k`
            );
        }

        videoffmpegCommand.push('-payload_type', `${payloadType}`, '-f', 'rtp');

        let targetProtocol = 'rtp';
        if (sessionInfo.videoCryptoSuite === SRTPCryptoSuites.AES_CM_128_HMAC_SHA1_80) {
            // actually ffmpeg just supports AES_CM_128_HMAC_SHA1_80

            // eslint-disable-next-line max-len
            videoffmpegCommand.push('-ssrc', `${sessionInfo.videoSSRC}`, '-srtp_out_suite', 'AES_CM_128_HMAC_SHA1_80', '-srtp_out_params', `${videoSRTP}`);
            targetProtocol = 'srtp';
        }

    // final destination URL must be a single arg
    videoffmpegCommand.push(`${targetProtocol}://${address}:${videoPort}?rtcpport=${videoPort}&localrtcpport=${videoPort}&pkt_size=${video.mtu}`);

    // Flatten and preserve values (do NOT split on spaces). Earlier pushes use individual args
    // for flags and keep header/user-agent values intact.
    const ffmpegCommandClean = videoffmpegCommand.flat().map(v => v.replace('%20', ' '));
        log.debug(`${this.blinkCamera.name} - ffmpeg ${ffmpegCommandClean.join(' ')}`);

        const ffmpegVideo = spawn(pathToFfmpeg || 'ffmpeg', ffmpegCommandClean, {env: process.env});
        this.ongoingSessions.set(sessionID, ffmpegVideo);
        this.pendingSessions.delete(sessionID);

        ffmpegVideo.stdout.on('data', data => log.debug(`${this.blinkCamera.name} - STDOUT: ${String(data)}`));
        // ffmpegVideo.stderr.on('data', data => log.debug(`${this.blinkCamera.name} - STDERR: ${String(data)}`));
        ffmpegVideo.on('error', error => {
            log.error(`${this.blinkCamera.name} - Failed to start ffmpeg: ${error?.message}`);
        });
        ffmpegVideo.on('exit', (code, signal) => {
            log.debug(`${this.blinkCamera.name} - ffmpeg ${signal}`);
            if (code !== null && code !== 255) {
                log.error(`${this.blinkCamera.name} - LiveView ERROR: ${signal} with code: ${code}`);
                this.blinkCamera.controller?.forceStopStreamingSession(sessionID);
            }
        });
    }

    async stopStream(sessionID) {
        log.info(`${this.blinkCamera?.name} - LiveView STOP`);

        if (this.proxySessions.has(sessionID)) {
            try {
                const rtspProxy = this.proxySessions.get(sessionID);
                await rtspProxy?.proxyServer?.stop();
            }
            catch (e) {
                log.error(`${this.blinkCamera?.name} - ERROR:`, e);
            }
            this.proxySessions.delete(sessionID);
        }
        if (this.ongoingSessions.has(sessionID)) {
            try {
                const ffmpegProcess = this.ongoingSessions.get(sessionID);
                ffmpegProcess?.kill('SIGKILL');
            }
            catch (e) {
                log.error(`${this.blinkCamera?.name} - Error occurred terminating the video process!`, e);
            }
            this.ongoingSessions.delete(sessionID);
        }
    }

    async createTLSTunnel(listenPort, targetHost, protocol) {
        const proxyServer = new Http2TLSTunnel(listenPort, targetHost, '0.0.0.0', 443, protocol);
        await proxyServer.start();
        return proxyServer;
    }
}

module.exports = BlinkCameraDelegate;
