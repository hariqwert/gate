const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const axios = require('axios');

const isWin = process.platform === 'win32';
const BIN_DIR = path.join(__dirname, '..', 'bin');
const DB_DIR = path.join(BIN_DIR, 'db');
const TORR_PORT = parseInt(process.env.TORR_INTERNAL_PORT || '8090', 10);
const TORR_BIN_NAME = isWin ? 'TorrServer.exe' : 'TorrServer';
const TORR_BIN_PATH = path.join(BIN_DIR, TORR_BIN_NAME);

let torrProcess = null;
let isStarting = false;
let isHealthy = false;
let startTime = 0;

if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

function getTorrBaseUrl() {
    return `http://127.0.0.1:${TORR_PORT}`;
}

async function checkTorrHealth(timeoutMs = 1500) {
    return new Promise((resolve) => {
        const req = http.get(`${getTorrBaseUrl()}/echo`, { timeout: timeoutMs }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                isHealthy = (res.statusCode === 200 && data.includes('MatriX'));
                resolve(isHealthy);
            });
        });
        req.on('error', () => {
            isHealthy = false;
            resolve(false);
        });
        req.on('timeout', () => {
            req.destroy();
            isHealthy = false;
            resolve(false);
        });
    });
}

async function ensureBinary() {
    if (fs.existsSync(TORR_BIN_PATH) && fs.statSync(TORR_BIN_PATH).size > 1000000) {
        return true;
    }

    console.log(`[TorrServer Keeper] Binary missing or invalid at ${TORR_BIN_PATH}. Downloading...`);
    const platform = process.platform;
    const arch = process.arch;
    let url = 'https://github.com/YouROK/TorrServer/releases/download/MatriX.134/TorrServer-linux-amd64';
    if (platform === 'linux' && (arch === 'arm64' || arch === 'aarch64')) {
        url = 'https://github.com/YouROK/TorrServer/releases/download/MatriX.134/TorrServer-linux-arm64';
    } else if (platform === 'win32') {
        url = 'https://github.com/YouROK/TorrServer/releases/download/MatriX.134/TorrServer-windows-amd64.exe';
    } else if (platform === 'darwin') {
        url = arch === 'arm64'
            ? 'https://github.com/YouROK/TorrServer/releases/download/MatriX.134/TorrServer-darwin-arm64'
            : 'https://github.com/YouROK/TorrServer/releases/download/MatriX.134/TorrServer-darwin-amd64';
    }

    return new Promise((resolve) => {
        function download(targetUrl, redirects = 0) {
            if (redirects > 5) {
                console.error('[TorrServer Keeper] Too many redirects downloading binary.');
                return resolve(false);
            }
            https.get(targetUrl, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    return download(res.headers.location, redirects + 1);
                }
                if (res.statusCode !== 200) {
                    console.error(`[TorrServer Keeper] Download failed with status ${res.statusCode}`);
                    return resolve(false);
                }
                const writer = fs.createWriteStream(TORR_BIN_PATH);
                res.pipe(writer);
                writer.on('finish', () => {
                    writer.close();
                    if (!isWin) {
                        try { fs.chmodSync(TORR_BIN_PATH, 0o755); } catch (e) {}
                    }
                    console.log('[TorrServer Keeper] Successfully downloaded TorrServer binary.');
                    resolve(true);
                });
                writer.on('error', (err) => {
                    console.error('[TorrServer Keeper] File write error:', err.message);
                    resolve(false);
                });
            }).on('error', (err) => {
                console.error('[TorrServer Keeper] Network download error:', err.message);
                resolve(false);
            });
        }
        download(url);
    });
}

async function configureTorrSettings() {
    const postData = JSON.stringify({
        action: 'set',
        sets: {
            CacheSize: 209715200, // 200MB RAM cache
            ConnectionsLimit: 150,
            PreloadCache: 5,
            ReaderReadAHead: 95,
            ResponsiveMode: true,
            RetrackersMode: 1,
            RemoveCacheOnDrop: true,
            TorrentDisconnectTimeout: 300,
            EnableDHT: true,
            EnablePEX: true,
            EnableIPv4: true,
            EnableIPv6: false
        }
    });

    return new Promise((resolve) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port: TORR_PORT,
            path: '/settings',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 3000
        }, (res) => {
            resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.write(postData);
        req.end();
    });
}

async function startTorrServer() {
    if (isStarting) return;
    isStarting = true;

    // Check if already running on the port
    if (await checkTorrHealth(1000)) {
        console.log(`⚡ [TorrServer Keeper] Engine already active and healthy on port ${TORR_PORT}`);
        isStarting = false;
        startTime = startTime || Date.now();
        await configureTorrSettings();
        return;
    }

    const binaryOk = await ensureBinary();
    if (!binaryOk) {
        console.error('❌ [TorrServer Keeper] Cannot start TorrServer: binary not found and download failed.');
        isStarting = false;
        return;
    }

    // Kill any orphan process on non-windows
    if (!isWin) {
        try { execSync('pkill -9 TorrServer || true'); } catch (e) {}
    }

    // Clean stale lock files
    const lockFile = path.join(DB_DIR, 'config.db.lock');
    if (fs.existsSync(lockFile)) {
        try { fs.unlinkSync(lockFile); } catch (e) {}
    }

    console.log(`🚀 [TorrServer Keeper] Spawning TorrServer on port ${TORR_PORT}...`);
    try {
        torrProcess = spawn(TORR_BIN_PATH, ['-p', String(TORR_PORT), '-d', DB_DIR], {
            cwd: BIN_DIR,
            env: { ...process.env, GOGC: '50', GOMEMLIMIT: '512MiB' }
        });

        startTime = Date.now();

        torrProcess.stdout.on('data', (d) => {
            const str = d.toString().trim();
            if (str && !str.includes('DEBUG')) {
                console.log(`[TorrServer Keeper] ${str}`);
            }
        });

        torrProcess.stderr.on('data', (d) => {
            const str = d.toString().trim();
            if (str) console.error(`[TorrServer Keeper Error] ${str}`);
        });

        torrProcess.on('close', (code) => {
            console.warn(`[TorrServer Keeper] Process exited with code ${code}`);
            isHealthy = false;
            torrProcess = null;
            if (code !== 0 && code !== null) {
                setTimeout(startTorrServer, 4000);
            }
        });

        torrProcess.on('error', (err) => {
            console.error('[TorrServer Keeper] Spawn error:', err.message);
            isHealthy = false;
            torrProcess = null;
        });

        // Wait for health check
        let retries = 15;
        while (retries > 0) {
            await new Promise(r => setTimeout(r, 400));
            if (await checkTorrHealth(1000)) {
                console.log(`✅ [TorrServer Keeper] Successfully running on port ${TORR_PORT}!`);
                await configureTorrSettings();
                break;
            }
            retries--;
        }
    } catch (e) {
        console.error('[TorrServer Keeper] Startup exception:', e.message);
    } finally {
        isStarting = false;
    }
}

/**
 * API Reverse Proxy for JSON control endpoints (/torrents, /settings, /echo, /viewed)
 */
async function proxyTorrApi(req, res) {
    const targetUrl = `${getTorrBaseUrl()}${req.originalUrl || req.url}`;
    try {
        let bodyObj = req.body;
        if (typeof bodyObj === 'string') {
            try { bodyObj = JSON.parse(bodyObj); } catch (e) {}
        }

        const payload = (req.method !== 'GET' && req.method !== 'HEAD' && bodyObj)
            ? (typeof bodyObj === 'string' ? bodyObj : bodyObj)
            : undefined;

        const response = await axios({
            method: req.method,
            url: targetUrl,
            data: payload,
            headers: {
                'Content-Type': req.headers['content-type'] || 'application/json',
                'User-Agent': req.headers['user-agent'] || 'AetherisGatekeeper'
            },
            timeout: 25000,
            validateStatus: () => true
        });

        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        res.status(response.status);

        if (typeof response.data === 'object') {
            res.setHeader('Content-Type', 'application/json');
            res.json(response.data);
        } else {
            res.send(response.data);
        }
    } catch (err) {
        if (!res.headersSent) {
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.status(502).json({
                status: 'error',
                message: 'TorrServer API service unavailable.',
                error: err.message
            });
        }
    }
}

/**
 * High-performance streaming reverse proxy forwarder for video media chunks
 * Supports Range requests (seeking), chunked transfer, and binary video piping
 */
function proxyTorrStream(req, res) {
    let forwardUrl = (req.url && req.url !== req.originalUrl) ? req.url : (req.originalUrl || req.url);
    forwardUrl = forwardUrl.replace(/^\/torr(?:web)?/, '') || '/';
    if (forwardUrl.includes('link=') && !forwardUrl.includes('play')) {
        forwardUrl += (forwardUrl.includes('?') ? '&' : '?') + 'play=1';
    }
    const parsedUrl = new URL(forwardUrl, getTorrBaseUrl());

    const cleanHeaders = { ...req.headers };
    delete cleanHeaders.host;
    delete cleanHeaders.origin;
    delete cleanHeaders.referer;
    cleanHeaders.host = `127.0.0.1:${TORR_PORT}`;

    const proxyReq = http.request({
        hostname: '127.0.0.1',
        port: TORR_PORT,
        path: parsedUrl.pathname + parsedUrl.search,
        method: req.method,
        headers: cleanHeaders
    }, (proxyRes) => {
        const proxyHeaders = {
            ...proxyRes.headers,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, HEAD',
            'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept, Range, Authorization',
            'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, Content-Type'
        };

        if (req.query && req.query.download === '1') {
            proxyHeaders['Content-Disposition'] = `attachment; filename="torrent_stream.mp4"`;
        }

        res.writeHead(proxyRes.statusCode || 200, proxyHeaders);
        proxyRes.pipe(res);
    });

    proxyReq.setNoDelay(true);
    proxyReq.setTimeout(0);

    const cleanup = () => {
        try { proxyReq.destroy(); } catch (e) {}
    };

    req.on('close', cleanup);
    req.on('aborted', cleanup);

    proxyReq.on('error', async (err) => {
        cleanup();
        if (res.headersSent || res.writableEnded) return;

        if (err.code === 'ECONNREFUSED' && !isStarting) {
            startTorrServer();
        }

        res.status(502).send('Torrent stream unavailable.');
    });

    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        proxyReq.end();
    } else {
        req.pipe(proxyReq, { end: true });
    }
}

function getStatus() {
    return {
        running: isHealthy || !!torrProcess,
        isHealthy,
        port: TORR_PORT,
        pid: torrProcess ? torrProcess.pid : null,
        uptimeSeconds: startTime ? Math.floor((Date.now() - startTime) / 1000) : 0,
        binaryPath: TORR_BIN_PATH
    };
}

// Graceful cleanup
process.on('exit', () => { if (torrProcess) torrProcess.kill(); });
process.on('SIGINT', () => { if (torrProcess) torrProcess.kill(); process.exit(); });
process.on('SIGTERM', () => { if (torrProcess) torrProcess.kill(); process.exit(); });

module.exports = {
    startTorrServer,
    proxyTorrApi,
    proxyTorrStream,
    checkTorrHealth,
    getStatus,
    getTorrBaseUrl
};
