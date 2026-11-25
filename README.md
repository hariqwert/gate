# 🛡️ Aetheris Passkey Gatekeeper & Security Guard

Standalone Zero-Trust Hardware Security Microservice & Biometric Passkey Portal for Stalker Pro 2.0.

## 🌐 Production Domains
- **Guard Portal**: `https://ellamkeeper.ai.studio`
- **Main Streaming Server**: `https://ellammoonu.ai.studio`
- **WebAuthn Relying Party (RP ID)**: `ellamkeeper.ai.studio`

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Run standalone on port 3050
npm start
```

---

## ⚙️ Environment Configuration

Set these environment variables in your cloud hosting provider (Render, Railway, Fly.io, etc.):

| Variable | Recommended Production Value | Description |
|---|---|---|
| `MAIN_SERVER_URL` | `https://ellammoonu.ai.studio` | URL of the main Stalker Pro streaming server |
| `GATE_BRIDGE_SECRET` | `aetheris_gate_secret_super_secure_2026` | Shared HMAC-SHA256 secret key |
| `GATE_PASSWORD` | `200812` | Heavy-string security passcode for the raw portal |
| `ADMIN_MASTER_KEY` | `AetherisGate2026!Master` | Master password for the Guard Admin Suite |
| `GATE_PORT` | `3050` | HTTP listening port (defaults to 3050 or `$PORT`) |
| `relyingPartyId` | `ellamkeeper.ai.studio` | FQDN domain for W3C WebAuthn biometric passkeys |

---

## 🔒 Security Features
1. **Heavy-String Passcode Shield**: Raw dashboard is masked until unlocked with passcode `200812`.
2. **HMAC-SHA512 + PBKDF2 (25,000 Rounds)**: Multi-stage cryptographic key stretching and constant-time comparison.
3. **W3C WebAuthn Biometrics**: Hardware-bound FaceID / TouchID / Windows Hello device registration.
4. **4-Hour Rotating PIN Sync**: Real-time bridge sync with `ellammoonu.ai.studio`.
