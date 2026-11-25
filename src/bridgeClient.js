const http = require('http');
const https = require('https');
const crypto = require('crypto');
const config = require('../config.json');

const GATE_BRIDGE_SECRET = process.env.GATE_BRIDGE_SECRET || config.bridgeSecret;
const MAIN_SERVER_URL = process.env.MAIN_SERVER_URL || config.mainServerUrl;
const GATE_INTERNAL_KEY = crypto.createHash('sha256').update(`${GATE_BRIDGE_SECRET}:internal_gatekeeper_v1`).digest('hex');

function requestMainServer(endpoint, method = 'GET', data = null) {
    return new Promise((resolve, reject) => {
        const u = new URL(endpoint, MAIN_SERVER_URL);
        const lib = u.protocol === 'https:' ? https : http;

        const timestampStr = Date.now().toString();
        const nonce = crypto.randomBytes(16).toString('hex');
        const bodyStr = (data && typeof data === 'object' && Object.keys(data).length > 0) ? JSON.stringify(data) : '';

        // Compute HMAC-SHA256 signature
        const payload = `${timestampStr}:${nonce}:${bodyStr}`;
        const signature = crypto.createHmac('sha256', GATE_BRIDGE_SECRET).update(payload).digest('hex');

        const headers = {
            'User-Agent': 'Aetheris-Gatekeeper-Bridge/2.0',
            'Accept': 'application/json',
            'x-gate-key': GATE_INTERNAL_KEY,
            'x-gate-timestamp': timestampStr,
            'x-gate-nonce': nonce,
            'x-gate-signature': signature
        };

        if (bodyStr) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = Buffer.byteLength(bodyStr);
        }

        const req = lib.request(u, {
            method,
            headers,
            timeout: 10000
        }, (res) => {
            let resBody = '';
            res.on('data', chunk => resBody += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(resBody);
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(parsed);
                    } else {
                        reject(new Error(parsed.message || `Server responded with HTTP ${res.statusCode}`));
                    }
                } catch (e) {
                    reject(new Error(`Invalid JSON response (HTTP ${res.statusCode}): ${resBody.slice(0, 100)}`));
                }
            });
        });

        req.on('error', err => reject(err));
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Main server connection timeout (10s)'));
        });

        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

module.exports = {
    fetchMainStatus: () => requestMainServer('/api/gate/status', 'GET'),
    fetchBoundDevices: () => requestMainServer('/api/gate/devices', 'GET'),
    bindNewDevice: (deviceData) => requestMainServer('/api/gate/bind-device', 'POST', deviceData),
    revokeBoundDevice: (deviceId) => requestMainServer('/api/gate/revoke-device', 'POST', { deviceId }),
    authorizeBoundDevice: (deviceId) => requestMainServer('/api/gate/authorize-device', 'POST', { deviceId }),
    deleteBoundDevice: (deviceId) => requestMainServer('/api/gate/delete-device', 'POST', { deviceId }),
    generateUnlockToken: (deviceId, deviceFingerprint) => requestMainServer('/api/gate/create-unlock-token', 'POST', { deviceId, deviceFingerprint }),
    forceRotatePin: () => requestMainServer('/api/gate/rotate-pin', 'POST', {})
};
