const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const config = require('./config.json');
const bridgeClient = require('./src/bridgeClient');
const tokenManager = require('./src/tokenManager');

const app = express();
const PORT = process.env.GATE_PORT || config.gatePort || 3050;
const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY || config.adminMasterKey;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function getClientIp(req) {
    const f = req.headers['x-forwarded-for'];
    if (typeof f === 'string') return f.split(',')[0].trim();
    return req.socket.remoteAddress || '127.0.0.1';
}

// --- HEAVY-STRING GATE PASSCODE ENGINE (Password: 200812) ---
const GATE_PASSWORD = String(process.env.GATE_PASSWORD || config.gatePassword || '200812').trim();
const HEAVY_SALT = 'AETHERIS_GATE_HEAVY_STRING_KEY_2026_x7719_SALT_HMAC_v1';

function heavyStringTransform(input) {
    if (!input || typeof input !== 'string') return '';
    const clean = input.trim();
    // Multi-stage HMAC-SHA512 + PBKDF2 25,000 rounds key stretching
    const stage1 = crypto.createHmac('sha512', HEAVY_SALT).update(clean, 'utf8').digest();
    const stage2 = crypto.pbkdf2Sync(stage1, HEAVY_SALT, 25000, 64, 'sha512');
    return crypto.createHmac('sha256', HEAVY_SALT).update(stage2).digest('hex');
}

const TARGET_HEAVY_HASH = heavyStringTransform(GATE_PASSWORD);

function verifyHeavyGatePassword(inputPass) {
    if (!inputPass || typeof inputPass !== 'string') return false;
    const computed = heavyStringTransform(inputPass);
    if (!computed || computed.length !== TARGET_HEAVY_HASH.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(TARGET_HEAVY_HASH, 'hex'));
    } catch {
        return false;
    }
}

// In-memory gate unlock sessions
const gateSessions = new Map(); // token -> { ip, createdAt, expiresAt }
const failedGateAttempts = new Map(); // ip -> { strikes, lockUntil }

function getCookie(req, name) {
    const raw = req.headers['cookie'];
    if (!raw) return null;
    const match = raw.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

function checkGateRateLimit(ip) {
    const now = Date.now();
    const entry = failedGateAttempts.get(ip);
    if (!entry) return { locked: false, remainingMins: 0, strikes: 0 };
    if (entry.lockUntil > now) {
        return { locked: true, remainingMins: Math.ceil((entry.lockUntil - now) / 60000), strikes: entry.strikes };
    }
    return { locked: false, remainingMins: 0, strikes: entry.strikes };
}

function recordGateFailure(ip) {
    const now = Date.now();
    const entry = failedGateAttempts.get(ip) || { strikes: 0, lockUntil: 0 };
    entry.strikes += 1;
    if (entry.strikes >= 5) {
        entry.lockUntil = now + (15 * 60 * 1000); // 15-minute lock
    }
    failedGateAttempts.set(ip, entry);
    return entry;
}

function clearGateStrikes(ip) {
    failedGateAttempts.delete(ip);
}

function isGateUnlocked(req) {
    const token = req.headers['x-gate-token'] || getCookie(req, 'gate_access_token');
    if (!token) return false;
    const session = gateSessions.get(token);
    if (!session) return false;
    if (Date.now() > session.expiresAt) {
        gateSessions.delete(token);
        return false;
    }
    return true;
}

// Simple in-memory session tokens for admin
const adminSessions = new Set();
const failedAdminLogins = new Map(); // IP -> { strikes, lockUntil }

function checkAdminRateLimit(ip) {
    const now = Date.now();
    const entry = failedAdminLogins.get(ip);
    if (!entry) return { locked: false, remainingMins: 0 };
    if (entry.lockUntil > now) {
        return { locked: true, remainingMins: Math.ceil((entry.lockUntil - now) / 60000) };
    }
    return { locked: false, remainingMins: 0 };
}

function recordAdminFailedLogin(ip) {
    const now = Date.now();
    const entry = failedAdminLogins.get(ip) || { strikes: 0, lockUntil: 0 };
    entry.strikes += 1;
    if (entry.strikes >= 5) {
        entry.lockUntil = now + (15 * 60 * 1000); // 15-minute lock
    }
    failedAdminLogins.set(ip, entry);
    return entry;
}

function clearAdminStrikes(ip) {
    failedAdminLogins.delete(ip);
}

function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    const keyHeader = req.headers['x-admin-key'];

    if ((keyHeader && keyHeader === ADMIN_MASTER_KEY) || (token && adminSessions.has(token))) {
        return next();
    }
    return res.status(401).json({ status: 'error', message: 'Unauthorized: Admin authentication required.' });
}

// =========================================================================
// 1. PUBLIC GATEKEEPER & PASSKEY APIS
// =========================================================================

/**
 * GET /api/gate/check
 * Verifies if the visitor has unlocked the gatekeeper
 */
app.get('/api/gate/check', (req, res) => {
    const unlocked = isGateUnlocked(req);
    return res.json({
        status: 'success',
        unlocked
    });
});

/**
 * POST /api/gate/unlock
 * Authenticates visitor using Heavy-String passcode (200812)
 */
app.post('/api/gate/unlock', async (req, res) => {
    const clientIp = getClientIp(req);
    const rl = checkGateRateLimit(clientIp);
    if (rl.locked) {
        return res.status(429).json({
            status: 'error',
            message: `Too many failed passcode attempts. Gate locked for ${rl.remainingMins} more minute(s).`
        });
    }

    const { password } = req.body || {};
    const cleanPass = String(password || '').trim();

    // Progressive delay for failed attempts
    if (rl.strikes > 0) {
        await new Promise(r => setTimeout(r, Math.min(rl.strikes * 400, 2000)));
    }

    const isValid = verifyHeavyGatePassword(cleanPass);
    if (!isValid) {
        const fail = recordGateFailure(clientIp);
        const remaining = Math.max(0, 5 - fail.strikes);
        return res.status(401).json({
            status: 'error',
            message: `Invalid Gatekeeper Passcode. (${remaining} attempt(s) remaining before 15m lockout)`
        });
    }

    clearGateStrikes(clientIp);
    const token = 'gate_' + crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24h
    gateSessions.set(token, { ip: clientIp, createdAt: Date.now(), expiresAt });

    res.setHeader('Set-Cookie', `gate_access_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
    return res.json({
        status: 'success',
        token,
        message: 'Gatekeeper unlocked successfully.'
    });
});

/**
 * POST /api/gate/lock
 * Clears gate session and re-locks the dashboard
 */
app.post('/api/gate/lock', (req, res) => {
    const token = req.headers['x-gate-token'] || getCookie(req, 'gate_access_token');
    if (token) {
        gateSessions.delete(token);
    }
    res.setHeader('Set-Cookie', 'gate_access_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
    return res.json({
        status: 'success',
        message: 'Gatekeeper locked.'
    });
});

/**
 * GET /api/status
 * Fetches real-time status from main streaming server via cryptographic bridge
 */
app.get('/api/status', async (req, res) => {
    const unlocked = isGateUnlocked(req);
    try {
        const data = await bridgeClient.fetchMainStatus();
        if (!unlocked) {
            return res.json({
                status: 'success',
                isGateLocked: true,
                mainServer: config.mainServerUrl,
                activePin: '••••••',
                message: 'Gatekeeper locked. Passcode verification required.'
            });
        }
        return res.json({
            status: 'success',
            isGateLocked: false,
            mainServer: config.mainServerUrl,
            ...data
        });
    } catch (err) {
        return res.status(502).json({
            status: 'error',
            message: 'Main streaming server is currently unreachable or offline.',
            error: err.message
        });
    }
});

/**
 * GET /api/invite/check
 * Verifies if a single-use invite token is valid and unburned
 */
app.get('/api/invite/check', (req, res) => {
    const token = String(req.query.token || '').trim();
    const result = tokenManager.checkInvite(token);
    if (!result.valid) {
        return res.status(404).json({ status: 'error', message: result.error });
    }
    return res.json({
        status: 'success',
        label: result.invite.label,
        expiresAt: result.invite.expiresAt
    });
});

/**
 * POST /api/passkey/enroll
 * Registers a new biometric device using a single-use invite token, then burns the token!
 */
app.post('/api/passkey/enroll', async (req, res) => {
    try {
        const { token, deviceId, deviceFingerprint, deviceLabel, publicKey, userAgent } = req.body || {};
        const clientIp = getClientIp(req);

        // 1. Validate invite token
        const check = tokenManager.checkInvite(token);
        if (!check.valid) {
            return res.status(403).json({ status: 'error', message: check.error });
        }

        if (!deviceId || !deviceFingerprint) {
            return res.status(400).json({ status: 'error', message: 'Missing hardware device identifiers.' });
        }

        // 2. Bind device on main streaming server via cryptographic bridge
        const bindResult = await bridgeClient.bindNewDevice({
            deviceId,
            deviceFingerprint,
            deviceLabel: deviceLabel || check.invite.label,
            publicKey: publicKey || '',
            userAgent: userAgent || req.headers['user-agent'] || 'Biometric Passkey Device'
        });

        // 3. BURN THE TOKEN PERMANENTLY!
        tokenManager.burnInvite(token, clientIp);

        // 4. Construct direct 1-click magic launch URL to main app
        const magicLaunchUrl = `${config.mainServerUrl}/hero.html?unlock_token=${encodeURIComponent(bindResult.unlockToken)}&bound_dev_id=${encodeURIComponent(deviceId)}&bound_dev_fp=${encodeURIComponent(deviceFingerprint || '')}&bound_dev_label=${encodeURIComponent(deviceLabel || '')}`;

        return res.json({
            status: 'success',
            message: 'Passkey registered successfully! Your device is now authorized.',
            device: bindResult.device,
            unlockToken: bindResult.unlockToken,
            magicLaunchUrl,
            expiresIn: bindResult.expiresIn
        });
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message || 'Passkey enrollment failed.' });
    }
});

/**
 * POST /api/passkey/auth
 * Fast biometric authentication for previously registered devices
 */
app.post('/api/passkey/auth', async (req, res) => {
    try {
        const { deviceId, deviceFingerprint } = req.body || {};
        if (!deviceId) {
            return res.status(400).json({ status: 'error', message: 'Missing deviceId.' });
        }

        const authResult = await bridgeClient.generateUnlockToken(deviceId, deviceFingerprint);
        const magicLaunchUrl = `${config.mainServerUrl}/hero.html?unlock_token=${encodeURIComponent(authResult.unlockToken)}&bound_dev_id=${encodeURIComponent(deviceId)}&bound_dev_fp=${encodeURIComponent(deviceFingerprint || '')}`;

        return res.json({
            status: 'success',
            message: 'Device verified via biometric passkey.',
            unlockToken: authResult.unlockToken,
            magicLaunchUrl,
            expiresIn: authResult.expiresIn
        });
    } catch (err) {
        return res.status(403).json({
            status: 'error',
            message: err.message || 'Device authorization rejected or revoked.'
        });
    }
});

// =========================================================================
// 2. COMPLETE ADMIN MANAGEMENT APIS
// =========================================================================

/**
 * POST /api/admin/login
 * Authenticates admin master passkey
 */
app.post('/api/admin/login', (req, res) => {
    const clientIp = getClientIp(req);
    const rl = checkAdminRateLimit(clientIp);
    if (rl.locked) {
        return res.status(429).json({
            status: 'error',
            message: `Too many failed admin login attempts. Locked for ${rl.remainingMins} more minute(s).`
        });
    }

    const { key } = req.body || {};
    const cleanKey = String(key || '').trim();
    const expectedKey = String(ADMIN_MASTER_KEY || '').trim();

    let matches = false;
    if (cleanKey && cleanKey.length === expectedKey.length) {
        try {
            matches = crypto.timingSafeEqual(Buffer.from(cleanKey, 'utf8'), Buffer.from(expectedKey, 'utf8'));
        } catch (_) {}
    }

    if (!matches) {
        const entry = recordAdminFailedLogin(clientIp);
        const remaining = Math.max(0, 5 - entry.strikes);
        return res.status(401).json({
            status: 'error',
            message: `Incorrect Admin Master Key. (${remaining} attempt(s) remaining before 15m lockout)`
        });
    }

    clearAdminStrikes(clientIp);
    const sessionToken = 'adm_' + crypto.randomBytes(24).toString('hex');
    adminSessions.add(sessionToken);

    return res.json({
        status: 'success',
        sessionToken,
        message: 'Admin authorization granted.'
    });
});

/**
 * GET /api/admin/dashboard
 * Aggregates complete live system overview for the admin suite
 */
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
    try {
        const status = await bridgeClient.fetchMainStatus().catch(() => ({ siteLocked: true, activePin: 'N/A' }));
        const deviceData = await bridgeClient.fetchBoundDevices().catch(() => ({ devices: [] }));
        const activeInvites = tokenManager.listActiveInvites();

        return res.json({
            status: 'success',
            telemetry: status,
            boundDevices: deviceData.devices || [],
            activeInvites,
            mainServerUrl: config.mainServerUrl
        });
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

/**
 * POST /api/admin/invites/create
 * Generates a single-use trusted invite link
 */
app.post('/api/admin/invites/create', requireAdmin, (req, res) => {
    const { label, ttlMinutes } = req.body || {};
    const invite = tokenManager.createInvite(label, ttlMinutes);
    const origin = req.headers.origin || `http://localhost:${PORT}`;
    const inviteUrl = `${origin}/enroll.html?token=${invite.token}`;

    return res.json({
        status: 'success',
        invite,
        inviteUrl
    });
});

/**
 * POST /api/admin/invites/cancel
 * Cancels a pending invite token
 */
app.post('/api/admin/invites/cancel', requireAdmin, (req, res) => {
    const { token } = req.body || {};
    const success = tokenManager.cancelInvite(token);
    return res.json({ status: success ? 'success' : 'error', cancelled: success });
});

/**
 * POST /api/admin/devices/revoke
 * Revokes authorization for a device
 */
app.post('/api/admin/devices/revoke', requireAdmin, async (req, res) => {
    try {
        const { deviceId } = req.body || {};
        const result = await bridgeClient.revokeBoundDevice(deviceId);
        return res.json(result);
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

/**
 * POST /api/admin/devices/authorize
 * Re-authorizes a device
 */
app.post('/api/admin/devices/authorize', requireAdmin, async (req, res) => {
    try {
        const { deviceId } = req.body || {};
        const result = await bridgeClient.authorizeBoundDevice(deviceId);
        return res.json(result);
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

/**
 * POST /api/admin/devices/delete
 * Permanently deletes a device
 */
app.post('/api/admin/devices/delete', requireAdmin, async (req, res) => {
    try {
        const { deviceId } = req.body || {};
        const result = await bridgeClient.deleteBoundDevice(deviceId);
        return res.json(result);
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

/**
 * POST /api/admin/pin/rotate
 * Forces an immediate rotation of the 4-hour PIN on the streaming server
 */
app.post('/api/admin/pin/rotate', requireAdmin, async (req, res) => {
    try {
        const result = await bridgeClient.forceRotatePin();
        return res.json(result);
    } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
    }
});

// =========================================================================
// 3. PAGE ROUTES
// =========================================================================

app.get('/enroll', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'enroll.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('==================================================================');
    console.log(`🛡️  Aetheris External Gatekeeper Portal running on port ${PORT}`);
    console.log(`📡 Linked to Main Streaming Server at: ${config.mainServerUrl}`);
    console.log(`👉 Member Portal: http://localhost:${PORT}/`);
    console.log(`👉 Admin Suite:  http://localhost:${PORT}/admin`);
    console.log('==================================================================');
});
