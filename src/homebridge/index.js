const path = require('path')
const { setLogger } = require('../log')
const hap = require('./hap')
const BLINK_STATUS_EVENT_LOOP = 10 // internal poll interval

class HomebridgeBlink {
    static get PLUGIN_NAME () {
        return 'homebridge-blink-for-home-new'
    }
    static get PLATFORM_NAME () {
        return 'Blink'
    }

    constructor (logger, config, api) {
        this.config = config || {}
        this.log = logger
        this.api = api
        setLogger(
            logger,
            ['verbose', 'debug'].includes(this.config['logging']),
            this.config['logging'] === 'debug'
        )

        this.accessoryLookup = []
        this.cachedAccessories = []

        this.accessories = {}
        this.disabled = false

        const hasTokens = Boolean(this.config.accessToken && this.config.refreshToken);
        if (!hasTokens) {
            this.disabled = true
            this.log.error(
                'Blink requires an access token and refresh token. Add both values in the Homebridge UI.'
            )
            this.log.error(
                'Blink platform initialisation skipped until credentials are provided.'
            )
            return
        }

        api.on('didFinishLaunching', () => this.init())
    }

    async init () {
        if (this.disabled) {
            this.log.warn(
                'Blink platform did not start because required credentials were missing.'
            )
            return
        }

        this.log.info('Init Blink')
        // const updateAccessories = function (data = [], accessories = new Map()) {
        //     for (const entry of data) {
        //         if (accessories.has(data.canonicalID)) accessories.get(data.canonicalID).data = entry;
        //     }
        // };
        //
        // const handleUpdates = data => updateAccessories(data, this.accessoryLookup);

        try {
            this.blink = await this.setupBlink()
            // TODO: signal updates? (alarm state?)
            // await this.conn.subscribe(handleUpdates);
            // await this.conn.observe(handleUpdates);

            const data = [
                ...this.blink.networks.values(),
                ...this.blink.cameras.values()
            ]
            this.accessoryLookup = data.map(entry =>
                entry.createAccessory(this.api, this.cachedAccessories)
            )

            this.api.unregisterPlatformAccessories(
                HomebridgeBlink.PLUGIN_NAME,
                HomebridgeBlink.PLATFORM_NAME,
                this.cachedAccessories
            )
            this.cachedAccessories = []
            this.api.registerPlatformAccessories(
                HomebridgeBlink.PLUGIN_NAME,
                HomebridgeBlink.PLATFORM_NAME,
                this.accessoryLookup
                    .map(blinkDevice => blinkDevice.accessory)
                    .filter(e => !!e)
            )

            // TODO: add new device discovery & removal
            await this.poll()

        } catch (err) {
            this.log.error(err)
            this.log.error(
                'NOTE: Blink devices in HomeKit will not be responsive.'
            )
            for (const accessory of this.cachedAccessories) {
                for (const service of accessory.services) {
                    for (const characteristic of service.characteristics) {
                        // reset getter and setter
                        characteristic.on('get', callback => callback('error'))
                        characteristic.on('set', (value, callback) =>
                            callback('error')
                        )
                        characteristic.getValue()
                    }
                }
            }
        }
    }

    async poll () {
        const intervalPoll = () => {
            if (this.timerID) clearInterval(this.timerID)
            this.poll()
        }

        try {
            // await this.blink.refreshCameraThumbnail();
            await this.blink.refreshData()
            await this.updateMotionCharacteristics()
        } catch (err) {
            this.log.error(err)
        }

        this.timerID = setInterval(intervalPoll, BLINK_STATUS_EVENT_LOOP * 1000)
    }

    async updateMotionCharacteristics (force = false) {
        if (!this.blink || !Array.isArray(this.accessoryLookup)) return

        const hapInstance = hap.hap
        if (!hapInstance || !hapInstance.Service || !hapInstance.Characteristic) return

        let motionEvents
        try {
            motionEvents = await this.blink.getMotionEvents(force, { backgroundRefresh: false })
        } catch (err) {
            this.log.error(err)
            return
        }
        const events = motionEvents instanceof Map ? motionEvents : new Map()
        const now = Date.now()

        for (const device of this.accessoryLookup) {
            if (!device?.accessory || device.cameraID === undefined) continue
            const detected = device.applyMotionState(events.get(device.cameraID) || null, now)
            const motionService = device.accessory.getService(hapInstance.Service.MotionSensor)
            if (motionService) {
                motionService.updateCharacteristic(
                    hapInstance.Characteristic.MotionDetected,
                    detected
                )
            }
        }
    }

    async setupBlink () {
        const hasTokens = Boolean(this.config.accessToken && this.config.refreshToken)
        const username = this.config.username || this.config.email
        const hasCredentials = Boolean(username && this.config.password)
        if (!hasTokens && !hasCredentials) {
            throw Error(
                'Blink requires either access/refresh tokens or your Blink username/password '
                + 'in the Homebridge configuration.'
            )
        }
        const uuidSeed = this.config.hardwareId || `${this.config.name || 'Blink'}`
        const clientUUID = this.config.hardwareId || this.api.hap.uuid.generate(uuidSeed)
        const auth = {
            hardwareId: clientUUID,
            clientUUID
        }
        if (hasCredentials) {
            auth.email = username
            auth.password = this.config.password
        }
        if (this.config.pin) auth.pin = this.config.pin
        const otp = this.config.otp || this.config.twoFactorCode || this.config.twoFactorToken
        if (otp) auth.otp = otp

        const oauthCachePath = path.join(
            this.api.user.storagePath(),
            'blink-oauth.json'
        )

        const { BlinkHAP } = require('./blink-hap')
        const blink = new BlinkHAP(clientUUID, auth, this.config, this.api)
        try {
            await blink.authenticate()
            await blink.refreshData()
            // TODO: move this off the startup loop?
            if (this.config['enable-startup-diagnostic'])
                await blink.diagnosticDebug()
        } catch (e) {
            this.log.error(e)
            throw new Error('Blink Authentication failed.')
        }

        return blink
    }

    configureAccessory (accessory) {
        this.cachedAccessories.push(accessory)
    }
}

module.exports = { HomebridgeBlink }
