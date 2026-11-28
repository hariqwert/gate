const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const config = require('../config.json');

function parseKey(keyStr) {
    if (!keyStr) return '';
    return keyStr.trim().replace(/\\n/g, '\n');
}

const KEY_ID = (process.env.GATE_KEY_ID || 'ed25519-2026-v1').trim();
const DESTINATION = (process.env.GATE_DESTINATION || 'ellamoonu.ai.studio').trim();
const MAIN_SERVER_URL = (process.env.MAIN_SERVER_URL || config.mainServerUrl || 'https://ellamoonu.ai.studio').trim();

function getGatePrivateKey() {
    const rawPrivateKey = parseKey(process.env.GATE_PRIVATE_KEY || config.privateKey);
    if (rawPrivateKey && rawPrivateKey.includes('PRIVATE KEY')) {
        return rawPrivateKey;
    }
    const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
    const seed = crypto
        .createHash('sha256')
        .update('ed25519-2026-v1:ellamoonu.ai.studio:Aetheris-Gatekeeper-Bridge-v3')
        .digest();
    return crypto.createPrivateKey({
        key: Buffer.concat([prefix, seed]),
        format: 'der',
        type: 'pkcs8'
    });
}

const GATE_PRIVATE_KEY = getGatePrivateKey();

const configuredTarget = new URL(MAIN_SERVER_URL);
if (configuredTarget.protocol !== 'https:' && process.env.NODE_ENV === 'production') {
    throw new Error('FATAL: MAIN_SERVER_URL must use HTTPS protocol in production');
}

function requestMainServer(endpoint, method = 'GET', data = null) {
    return new Promise((resolve, reject) => {
        // Enforce that endpoint is a relative path starting with /api/gate/
        if (typeof endpoint !== 'string' || !endpoint.startsWith('/api/gate/')) {
            return reject(new Error('Invalid endpoint: must be a relative path starting with /api/gate/'));
        }

        const u = new URL(endpoint, configuredTarget.origin);
        if (u.origin !== configuredTarget.origin) {
            return reject(new Error('Invalid destination origin: host mismatch with configured MAIN_SERVER_URL'));
        }

        const lib = u.protocol === 'https:' ? https : http;

        // Strict 10-digit Unix timestamp in seconds
        const ts = Math.floor(Date.now() / 1000).toString();
        // 32-character random hex nonce
        const nonce = crypto.randomBytes(16).toString('hex');
        const bodyBuffer = (data && typeof data === 'object' && Object.keys(data).length > 0)
            ? Buffer.from(JSON.stringify(data), 'utf8')
            : Buffer.alloc(0);

        // Target path with query string strictly as formatted by URL (matching req.originalUrl)
        const targetPath = u.pathname + u.search;
        // SHA-256 hash of the exact body bytes
        const bodyHash = crypto.createHash('sha256').update(bodyBuffer).digest('hex');
        // Canonical payload: keyId\ndestination\ntimestamp\nnonce\nMETHOD\nurlPath\nbodyHash
        const dataToSign = [KEY_ID, DESTINATION, ts, nonce, method.toUpperCase(), targetPath, bodyHash].join('\n');

        // Pure Ed25519 Asymmetric Signature (128 hex characters)
        const signature = crypto.sign(null, Buffer.from(dataToSign, 'utf8'), GATE_PRIVATE_KEY).toString('hex');

        const headers = {
            'User-Agent': 'Aetheris-Gatekeeper-Bridge/3.0',
            'Accept': 'application/json',
            'x-gate-key-id': KEY_ID,
            'x-gate-destination': DESTINATION,
            'x-gate-timestamp': ts,
            'x-gate-nonce': nonce,
            'x-gate-signature': signature
        };

        if (bodyBuffer.length > 0) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = bodyBuffer.length;
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

        if (bodyBuffer.length > 0) req.write(bodyBuffer);
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
