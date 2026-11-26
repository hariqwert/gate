const http = require('http');
const https = require('https');
const crypto = require('crypto');
const config = require('../config.json');

// Asymmetric Ed25519 Private Key: The Gatekeeper uses this to sign requests.
// The main server holds ONLY the corresponding public key and cannot forge signatures.
const DEFAULT_GATE_ED25519_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICmIzEAqnicsaL39MoyIZv3V0LhL6BeyYrf2piwnzQL+
-----END PRIVATE KEY-----`;

const GATE_PRIVATE_KEY = (process.env.GATE_PRIVATE_KEY || config.privateKey || DEFAULT_GATE_ED25519_PRIVATE_KEY).trim();
const GATE_BRIDGE_SECRET = (process.env.GATE_BRIDGE_SECRET || config.bridgeSecret || 'aetheris_gate_secret_super_secure_2026').trim();
const MAIN_SERVER_URL = (process.env.MAIN_SERVER_URL || config.mainServerUrl || 'https://ellamoonu.ai.studio').trim();

function requestMainServer(endpoint, method = 'GET', data = null) {
    return new Promise((resolve, reject) => {
        const u = new URL(endpoint, MAIN_SERVER_URL);
        const lib = u.protocol === 'https:' ? https : http;

        // Strict 10-digit Unix timestamp in seconds
        const ts = Math.floor(Date.now() / 1000).toString();
        // 32-character random hex nonce
        const nonce = crypto.randomBytes(16).toString('hex');
        const bodyStr = (data && typeof data === 'object' && Object.keys(data).length > 0) ? JSON.stringify(data) : '';
        const bodyBuffer = Buffer.from(bodyStr, 'utf8');

        // Target path with query string as seen by main server
        const targetPath = u.pathname + u.search;
        // SHA-256 hash of the exact body bytes
        const bodyHash = crypto.createHash('sha256').update(bodyBuffer).digest('hex');
        // Canonical payload: timestamp\nnonce\nMETHOD\nurlPath\nbodyHash
        const dataToSign = [ts, nonce, method.toUpperCase(), targetPath, bodyHash].join('\n');

        let signature = '';
        if (GATE_PRIVATE_KEY) {
            // Ed25519 Asymmetric Signature (128 hex characters)
            signature = crypto.sign(null, Buffer.from(dataToSign, 'utf8'), GATE_PRIVATE_KEY).toString('hex');
        } else {
            // HMAC-SHA256 Fallback (64 hex characters)
            signature = crypto.createHmac('sha256', GATE_BRIDGE_SECRET).update(dataToSign).digest('hex');
        }

        const headers = {
            'User-Agent': 'Aetheris-Gatekeeper-Bridge/3.0',
            'Accept': 'application/json',
            'x-gate-timestamp': ts,
            'x-gate-nonce': nonce,
            'x-gate-signature': signature
        };

        if (bodyStr) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = Buffer.byteLength(bodyBuffer);
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

        if (bodyStr) req.write(bodyBuffer);
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
