const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config.json');

const INVITES_FILE = path.join(__dirname, '..', 'data', 'invites.json');
const activeInvites = new Map();

function ensureDataDir() {
    const dir = path.dirname(INVITES_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadInvites() {
    try {
        ensureDataDir();
        if (fs.existsSync(INVITES_FILE)) {
            const raw = JSON.parse(fs.readFileSync(INVITES_FILE, 'utf8'));
            const now = Date.now();
            activeInvites.clear();
            if (Array.isArray(raw)) {
                for (const item of raw) {
                    if (item && item.token && item.expiresAt > now && !item.used) {
                        activeInvites.set(item.token, item);
                    }
                }
            }
        }
    } catch (_) {
        activeInvites.clear();
    }
}

function persistInvites() {
    try {
        ensureDataDir();
        const arr = Array.from(activeInvites.values());
        fs.writeFileSync(INVITES_FILE, JSON.stringify(arr, null, 2), 'utf8');
    } catch (_) {}
}

loadInvites();

module.exports = {
    /**
     * Create a single-use trusted invite token
     */
    createInvite(label = 'Trusted Friend Device', ttlMinutes = null) {
        const ttl = (ttlMinutes || config.inviteTokenTtlMinutes || 15) * 60 * 1000;
        const now = Date.now();
        // High entropy 32-character hex token
        const token = 'inv_' + crypto.randomBytes(16).toString('hex');

        const invite = {
            token,
            label: String(label).trim().slice(0, 64) || 'Trusted Biometric Device',
            createdAt: now,
            expiresAt: now + ttl,
            used: false,
            usedAt: null,
            usedByIp: null
        };

        activeInvites.set(token, invite);
        persistInvites();
        return invite;
    },

    /**
     * Verify invite token status without burning
     */
    checkInvite(token) {
        if (!token) return { valid: false, error: 'Missing invite token.' };
        const invite = activeInvites.get(token);
        if (!invite) return { valid: false, error: 'Invalid or already burned invite token.' };

        if (invite.used) {
            return { valid: false, error: 'This invite token has already been redeemed and burned.' };
        }

        if (Date.now() > invite.expiresAt) {
            activeInvites.delete(token);
            persistInvites();
            return { valid: false, error: 'This invite token has expired.' };
        }

        return { valid: true, invite };
    },

    /**
     * Burn / Consume invite token permanently upon successful Passkey enrollment
     */
    burnInvite(token, clientIp = '127.0.0.1') {
        const check = this.checkInvite(token);
        if (!check.valid) return false;

        const invite = check.invite;
        invite.used = true;
        invite.usedAt = Date.now();
        invite.usedByIp = clientIp;

        // Permanently delete so it can never be reused
        activeInvites.delete(token);
        persistInvites();
        return true;
    },

    /**
     * List all unexpired pending invites for the Admin dashboard
     */
    listActiveInvites() {
        const now = Date.now();
        const list = [];
        for (const [token, inv] of activeInvites.entries()) {
            if (inv.expiresAt > now && !inv.used) {
                list.push({
                    token: inv.token,
                    label: inv.label,
                    createdAt: inv.createdAt,
                    expiresAt: inv.expiresAt,
                    remainingSeconds: Math.max(0, Math.round((inv.expiresAt - now) / 1000))
                });
            } else {
                activeInvites.delete(token);
            }
        }
        return list;
    },

    /**
     * Revoke / Cancel a pending invite
     */
    cancelInvite(token) {
        if (activeInvites.has(token)) {
            activeInvites.delete(token);
            persistInvites();
            return true;
        }
        return false;
    }
};
