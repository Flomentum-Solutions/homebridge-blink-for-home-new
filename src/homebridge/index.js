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

        const hasLegacyCredentials = Boolean(this.config.username && this.config.password);
        const hasOAuthTokens = Boolean(this.config.accessToken || this.config.refreshToken);
        if (!hasLegacyCredentials && !hasOAuthTokens) {
            this.disabled = true
            this.log.error(
                'Blink requires OAuth tokens or legacy credentials. Launch the Homebridge UI to sign in.'
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

        // await this.blink.refreshCameraThumbnail();
        try {
            await this.blink.refreshData()
        } catch (err) {
            this.log.error(err)
        }

        this.timerID = setInterval(intervalPoll, BLINK_STATUS_EVENT_LOOP * 1000)
    }

    async setupBlink () {
        const hasLegacyCredentials = Boolean(this.config.username && this.config.password)
        const hasOAuthTokens = Boolean(this.config.accessToken || this.config.refreshToken)
        if (!hasLegacyCredentials && !hasOAuthTokens) {
            throw Error('Missing Blink credentials or OAuth tokens in config.json')
        }
        const uuidSeed = `${this.config.name || 'Blink'}:${this.config.username || ''}`
        const clientUUID = this.config.hardwareId || this.api.hap.uuid.generate(uuidSeed)
        const auth = {
            email: this.config.username,
            password: this.config.password,
            pin: this.config.pin,
            hardwareId: clientUUID,
            clientUUID
        }

        const oauthCachePath = path.join(
            this.api.user.storagePath(),
            'blink-oauth.json'
        )

        const { BlinkHAP } = require('./blink-hap')
        const blink = new BlinkHAP(clientUUID, auth, {
            ...this.config,
            tokenCachePath: oauthCachePath
        })
        blink.blinkAPI._clientOptions = Object.assign(
            {},
            blink.blinkAPI._clientOptions,
            {
                hardwareId: auth.hardwareId || blink.blinkAPI._clientOptions?.hardwareId,
                oauthClientId: this.config.oauthClientId || blink.blinkAPI._clientOptions?.oauthClientId,
                oauthScope: this.config.oauthScope || blink.blinkAPI._clientOptions?.oauthScope,
            }
        )
        if (this.config.accessToken || this.config.refreshToken) {
            blink.blinkAPI.useOAuthBundle({
                access_token: this.config.accessToken,
                refresh_token: this.config.refreshToken,
                expires_at: this.config.tokenExpiresAt,
                account_id: this.config.accountId,
                client_id: this.config.clientId,
                region: this.config.region,
            })
        }
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
