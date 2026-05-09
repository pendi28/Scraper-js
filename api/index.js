/**
 * api/index.js
 * Express API + built-in scraping engine
 * - GET /api/catalog        → daftar drama (dramas_catalog.json)
 * - GET /api/episodes/:id   → ambil episode, auto-scrape jika belum ada
 * - GET /api/decrypt?url=   → proxy decrypt video
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const http    = require('http');
const tls     = require('tls');
const crypto  = require('crypto');
const zlib    = require('zlib');
const axios   = require('axios');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

// ─── Config Scraper ───────────────────────────────────────────────────────────
const API_BASE    = 'https://nb-dramabox-gentoken.vercel.app';
const TIMEOUT_MS  = 12000;
const MAX_RETRIES = 4;
const TMP_DIR     = '/tmp';   // Vercel writable temp

// Session shared di-reuse selama instance hidup
const session = {
    token: '', deviceid: '', androidid: '',
    instanceid: crypto.randomBytes(16).toString('hex'),
    afid: `${Date.now()}-${Math.floor(Math.random() * 9999999999999999)}`,
    ins: Date.now().toString(),
    st: 'cK4n10B_0tTQBrxFyyBWnOKD',
    cookies: [],
    ready: false
};

// ─── Scraper Engine ───────────────────────────────────────────────────────────
function getLocalTime() {
    const bt  = new Date(Date.now() + 7 * 3600000);
    const p   = n => n.toString().padStart(2, '0');
    return `${bt.getUTCFullYear()}-${p(bt.getUTCMonth()+1)}-${p(bt.getUTCDate())} ` +
           `${p(bt.getUTCHours())}:${p(bt.getUTCMinutes())}:${p(bt.getUTCSeconds())}.` +
           `${bt.getUTCMilliseconds().toString().padStart(3,'0')} +0700`;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function ensureToken() {
    if (session.ready) return true;
    try {
        const res = await axios.get(`${API_BASE}/generate-token`, { timeout: TIMEOUT_MS });
        if (res.data?.status && res.data?.data) {
            Object.assign(session, {
                token:     res.data.data.sn,
                deviceid:  res.data.data.device_id,
                androidid: res.data.data.android_id,
                cookies:   [],
                ready:     true
            });
            return true;
        }
    } catch {}
    return false;
}

async function getSignature(body) {
    try {
        const res = await axios.post(`${API_BASE}/sign`, {
            body, device_id: session.deviceid,
            android_id: session.androidid, token: session.token
        }, { timeout: TIMEOUT_MS });
        return res.data?.status ? res.data.data : null;
    } catch { return null; }
}

function buildHeaders(sn, token) {
    return {
        'accept-encoding': 'gzip', 'version': '580',
        'package-name': 'com.storymatrix.drama', 'p': '63',
        'cid': 'DRA1000042', 'apn': '2', 'country-code': 'ID',
        'mchid': 'DRA1000042', 'tz': '-420', 'language': 'in',
        'mcc': '510', 'locale': 'in_ID', 'is_root': '0',
        'device-id': session.deviceid, 'nchid': 'DRA1000042',
        'instanceid': session.instanceid, 'md': 'Redmi Note 5',
        'store-source': 'store_google', 'mf': 'XIAOMI', 'device-score': '60',
        'local-time': getLocalTime(), 'time-zone': '+0700', 'brand': 'Xiaomi',
        'lat': '0', 'is_emulator': '0', 'current-language': 'in', 'ov': '10',
        'afid': session.afid, 'android-id': session.androidid,
        'srn': '1080x2160', 'ins': session.ins, 'is_vpn': '1',
        'build': 'Build/QQ3A.200805.001', 'pline': 'ANDROID', 'vn': '5.8.0',
        'over-flow': 'new-fly', 'tn': token ? `Bearer ${token}` : '',
        'sn': sn, 'st': session.st,
        'active-time': Math.floor(Math.random() * 20000).toString(),
        'content-type': 'application/json; charset=UTF-8',
        'user-agent': 'okhttp/4.12.0'
    };
}

function wRequest(urlStr, bodyObj, headers) {
    return new Promise(resolve => {
        const u   = new URL(urlStr);
        const str = JSON.stringify(bodyObj);
        if (session.cookies.length) headers['Cookie'] = session.cookies.join('; ');

        let raw = `POST ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
        for (const [k, v] of Object.entries(headers))
            if (!['host', 'content-length', 'cookie'].includes(k.toLowerCase()))
                raw += `${k}: ${v}\r\n`;
        if (headers['Cookie']) raw += `Cookie: ${headers['Cookie']}\r\n`;
        raw += `Content-Length: ${Buffer.byteLength(str)}\r\nConnection: close\r\n\r\n${str}`;

        let sock;
        try {
            sock = tls.connect({
                host: u.hostname, port: 443, servername: u.hostname,
                rejectUnauthorized: false,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256',
                ALPNProtocols: ['http/1.1']
            }, () => sock.write(raw));
        } catch (e) {
            return resolve({ success: false, error: e.message });
        }

        let buf = Buffer.alloc(0);
        sock.on('data', d => buf = Buffer.concat([buf, d]));
        sock.on('end', () => {
            const s   = buf.toString('binary');
            const idx = s.indexOf('\r\n\r\n');
            if (idx === -1) return resolve({ success: false, error: 'Bad HTTP' });

            const hPart = s.substring(0, idx);
            let body    = buf.subarray(idx + 4);
            const code  = parseInt(hPart.split('\r\n')[0].split(' ')[1], 10);

            const h = {};
            hPart.split('\r\n').slice(1).forEach(line => {
                const p = line.split(':');
                if (p.length > 1) {
                    const key = p[0].trim().toLowerCase();
                    const val = p.slice(1).join(':').trim();
                    h[key] = key === 'set-cookie' ? [...(h[key] || []), val] : val;
                }
            });

            if (h['st']) session.st = h['st'];
            if (h['set-cookie']) h['set-cookie'].forEach(cs => {
                const main = cs.split(';')[0];
                session.cookies = session.cookies.filter(c => !c.startsWith(main.split('=')[0] + '='));
                session.cookies.push(main);
            });

            if (code >= 400) return resolve({ success: false, error: `HTTP ${code}` });

            if (h['content-encoding'] === 'gzip') {
                try { body = zlib.gunzipSync(body); } catch {}
            }
            let finalStr = body.toString('utf8');
            if (h['transfer-encoding'] === 'chunked') {
                const a = finalStr.indexOf('{'), b = finalStr.lastIndexOf('}');
                if (a !== -1 && b !== -1) finalStr = finalStr.substring(a, b + 1);
            }
            try { resolve({ success: true, data: JSON.parse(finalStr) }); }
            catch { resolve({ success: false, error: 'JSON error' }); }
        });
        sock.on('error', e => resolve({ success: false, error: e.message }));
        sock.setTimeout(TIMEOUT_MS);
        sock.on('timeout', () => { sock.destroy(); resolve({ success: false, error: 'Timeout' }); });
    });
}

async function postData(endpoint, body) {
    const sign = await getSignature(body);
    if (!sign) return { success: false, error: 'Signature gagal' };
    const headers = buildHeaders(sign.sn, session.token);
    const sep = endpoint.includes('?') ? '&' : '?';
    const res = await wRequest(`${endpoint}${sep}timestamp=${sign.timestamp}`, body, headers);
    return res.success && res.data?.data
        ? { success: true, data: res.data.data }
        : { success: false, error: res.error || 'Data kosong' };
}

// ─── Scrape katalog drama ──────────────────────────────────────────────────────
async function fetchCatalog() {
    let page = 1, all = [];
    while (true) {
        const body = {
            newChannelStyle: 1, isNeedRank: 1, pageNo: page,
            index: 1, channelId: 43,
            recSessionId: crypto.randomBytes(32).toString('hex')
        };
        const res = await postData('https://sapi.dramaboxvideo.com/drama-box/he001/theater', body);
        if (res.success && res.data?.newTheaterList?.records?.length > 0) {
            all.push(...res.data.newTheaterList.records);
            if (page >= (res.data.newTheaterList.pages || 1)) break;
            page++;
            await sleep(600);
        } else break;
    }
    return all.map(item => ({
        bookId:   item.bookId,
        title:    item.bookName || item.name || 'Unknown',
        cover:    item.cover || item.coverWap || '',
        totalEps: item.chapterCount || item.totalChapter || 0,
        status:   item.serialStatus === 1 ? 'Ongoing' : 'Completed',
        tags:     (item.labelList || []).map(l => l.name).join(', ')
    }));
}

// ─── Scrape semua episode satu drama ─────────────────────────────────────────
async function fetchEpisodes(bookId) {
    let all = [], cursor = -1, batch = 1, retries = 0;

    while (true) {
        const body = {
            boundaryIndex: 0, index: parseInt(cursor),
            currencyPlaySource: 'discover_175_rec', needEndRecommend: 0,
            currencyPlaySourceName: '首页发现_Untukmu_推荐列表',
            preLoad: false, rid: '', pullCid: '',
            enterReaderChapterIndex: 0,
            loadDirection: cursor === -1 ? 0 : 2,
            startUpKey: crypto.randomUUID(),
            bookId: String(bookId)
        };

        const res = await postData('https://sapi.dramaboxvideo.com/drama-box/chapterv2/batch/load', body);
        const isEmpty = res.success && !res.data?.chapterList?.length;

        if (!res.success || isEmpty) {
            retries++;
            if (retries >= MAX_RETRIES) break;
            if (retries % 2 === 0) {
                session.ready = false;
                await ensureToken();
            }
            if (cursor !== -1) cursor += 5;
            await sleep(1500 + Math.random() * 1000);
            continue;
        }

        retries = 0;
        const newEps = res.data.chapterList.filter(n => !all.some(e => e.chapterId === n.chapterId));
        if (!newEps.length) { cursor += 5; retries++; }
        else {
            all.push(...newEps);
            cursor = parseInt(newEps[newEps.length - 1].chapterIndex);
        }
        batch++;
        await sleep(700 + Math.random() * 500);
    }

    if (all.length > 0) {
        all.sort((a, b) => a.chapterIndex - b.chapterIndex);
        // Hapus semua field lock/VIP
        return all.map(ep => {
            const out = { ...ep };
            delete out.isCharge; delete out.chargeChapter;
            if (out.cdnList) out.cdnList = out.cdnList.map(cdn => ({
                ...cdn,
                videoPathList: (cdn.videoPathList || []).map(v => {
                    const vv = { ...v }; delete vv.isVipEquity; return vv;
                })
            }));
            return out;
        });
    }
    return [];
}

// ─── Format episode → URL siap putar ─────────────────────────────────────────
function formatEpisodes(rawData, baseUrl) {
    return rawData.map((ep, i) => {
        const title = ep.chapterName || `Episode ${i + 1}`;
        const cdn   = ep.cdnList
            ? (ep.cdnList.find(c => c.isDefault === 1) || ep.cdnList[0])
            : null;
        const vid   = cdn?.videoPathList
            ? (cdn.videoPathList.find(v => v.isDefault === 1) || cdn.videoPathList[0])
            : null;

        const rawUrl = vid?.videoPath || '';
        const playUrl = rawUrl
            ? `${baseUrl}/api/decrypt?url=${encodeURIComponent(rawUrl)}`
            : '';

        const sources = (cdn?.videoPathList || [])
            .filter(v => v.videoPath)
            .map(v => ({
                quality: v.quality,
                url: `${baseUrl}/api/decrypt?url=${encodeURIComponent(v.videoPath)}`
            }));

        return { title, chapterIndex: ep.chapterIndex, playUrl, sources, thumbnailUrl: ep.chapterImg || ep.spriteSnapshotUrl || '' };
    });
}

// ─── Cache path helper ────────────────────────────────────────────────────────
function episodePaths(bookId) {
    const filename = `raw_episodes_${bookId}.json`;
    return {
        repo: path.resolve(process.cwd(), filename),
        tmp:  path.join(TMP_DIR, filename)
    };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/catalog
app.get('/api/catalog', async (req, res) => {
    // 1. Coba baca dari repo
    const repoPath = path.resolve(process.cwd(), 'dramas_catalog.json');
    if (fs.existsSync(repoPath)) {
        return res.json(JSON.parse(fs.readFileSync(repoPath, 'utf8')));
    }

    // 2. Auto-scrape
    await ensureToken();
    const catalog = await fetchCatalog();
    if (!catalog.length) return res.status(502).json({ error: 'Gagal ambil katalog drama.' });

    // Simpan ke /tmp untuk cache
    try { fs.writeFileSync(path.join(TMP_DIR, 'dramas_catalog.json'), JSON.stringify(catalog)); } catch {}
    res.json(catalog);
});

// GET /api/episodes/:id — auto-scrape jika belum ada
app.get('/api/episodes/:id', async (req, res) => {
    const bookId = req.params.id;
    const { repo, tmp } = episodePaths(bookId);
    const baseUrl = `${req.protocol}://${req.get('host')}`;

    // 1. Coba dari repo
    if (fs.existsSync(repo)) {
        const raw = JSON.parse(fs.readFileSync(repo, 'utf8'));
        return res.json(formatEpisodes(raw, baseUrl));
    }

    // 2. Coba dari /tmp cache
    if (fs.existsSync(tmp)) {
        const raw = JSON.parse(fs.readFileSync(tmp, 'utf8'));
        return res.json(formatEpisodes(raw, baseUrl));
    }

    // 3. Auto-scrape langsung dari server
    const ok = await ensureToken();
    if (!ok) return res.status(502).json({ error: 'Gagal inisialisasi session scraper.' });

    const raw = await fetchEpisodes(bookId);
    if (!raw.length) return res.status(502).json({ error: `Gagal scrape episode untuk bookId ${bookId}.` });

    // Simpan ke /tmp untuk request berikutnya
    try { fs.writeFileSync(tmp, JSON.stringify(raw)); } catch {}

    res.json(formatEpisodes(raw, baseUrl));
});

// GET /api/decrypt?url=
app.get('/api/decrypt', (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }

    const proxyUrl = `https://nb-dramabox-gentoken.vercel.app/decrypt-video?url=${encodeURIComponent(url)}`;
    const client   = https;

    const proxyReq = client.get(proxyUrl, proxyRes => {
        res.status(proxyRes.statusCode || 200);
        if (proxyRes.headers['content-type'])   res.setHeader('Content-Type', proxyRes.headers['content-type']);
        if (proxyRes.headers['content-length'])  res.setHeader('Content-Length', proxyRes.headers['content-length']);
        if (proxyRes.headers['accept-ranges'])   res.setHeader('Accept-Ranges', proxyRes.headers['accept-ranges']);
        res.setHeader('Cache-Control', 'public, max-age=3600');
        proxyRes.pipe(res);
    });
    proxyReq.on('error', err => { if (!res.headersSent) res.status(502).json({ error: err.message }); });
    req.on('close', () => proxyReq.destroy());
});

// Fallback → index.html
app.get('*', (req, res) => {
    const p = path.join(__dirname, '../public/index.html');
    fs.existsSync(p) ? res.sendFile(p) : res.status(404).send('Not found');
});

module.exports = app;
