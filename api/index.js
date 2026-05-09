/**
 * api/index.js — DramaBox API + Auto-Scrape Engine
 * Routes:
 *   GET /api/catalog        → daftar drama
 *   GET /api/episodes/:id   → episode (auto-scrape jika belum ada)
 *   GET /api/decrypt?url=   → proxy decrypt video
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const tls     = require('tls');
const crypto  = require('crypto');
const zlib    = require('zlib');
const axios   = require('axios');

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

// ─── Config ───────────────────────────────────────────────────────────────────
const API_BASE   = 'https://nb-dramabox-gentoken.vercel.app';
const TIMEOUT_MS = 10000;
const MAX_RETRY  = 3;
const TMP        = '/tmp';

// Session — reuse selama instance Vercel hidup
const session = {
    token:'', deviceid:'', androidid:'',
    instanceid: crypto.randomBytes(16).toString('hex'),
    afid: `${Date.now()}-${Math.floor(Math.random()*9999999999)}`,
    ins: Date.now().toString(),
    st: 'cK4n10B_0tTQBrxFyyBWnOKD',
    cookies: [], ready: false
};

// ─── Scraper Helpers ──────────────────────────────────────────────────────────
function localTime() {
    const bt = new Date(Date.now() + 7*3600000);
    const p  = n => n.toString().padStart(2,'0');
    return `${bt.getUTCFullYear()}-${p(bt.getUTCMonth()+1)}-${p(bt.getUTCDate())} ` +
           `${p(bt.getUTCHours())}:${p(bt.getUTCMinutes())}:${p(bt.getUTCSeconds())}.` +
           `${bt.getUTCMilliseconds().toString().padStart(3,'0')} +0700`;
}

async function ensureToken() {
    if (session.ready) return true;
    try {
        const r = await axios.get(`${API_BASE}/generate-token`, { timeout: TIMEOUT_MS });
        if (r.data?.status && r.data?.data) {
            Object.assign(session, {
                token: r.data.data.sn, deviceid: r.data.data.device_id,
                androidid: r.data.data.android_id, cookies: [], ready: true
            });
            return true;
        }
    } catch {}
    return false;
}

async function sign(body) {
    try {
        const r = await axios.post(`${API_BASE}/sign`, {
            body, device_id: session.deviceid,
            android_id: session.androidid, token: session.token
        }, { timeout: TIMEOUT_MS });
        return r.data?.status ? r.data.data : null;
    } catch { return null; }
}

function headers(sn, token) {
    return {
        'accept-encoding':'gzip','version':'580','package-name':'com.storymatrix.drama',
        'p':'63','cid':'DRA1000042','apn':'2','country-code':'ID','mchid':'DRA1000042',
        'tz':'-420','language':'in','mcc':'510','locale':'in_ID','is_root':'0',
        'device-id':session.deviceid,'nchid':'DRA1000042','instanceid':session.instanceid,
        'md':'Redmi Note 5','store-source':'store_google','mf':'XIAOMI','device-score':'60',
        'local-time':localTime(),'time-zone':'+0700','brand':'Xiaomi','lat':'0',
        'is_emulator':'0','current-language':'in','ov':'10','afid':session.afid,
        'android-id':session.androidid,'srn':'1080x2160','ins':session.ins,'is_vpn':'1',
        'build':'Build/QQ3A.200805.001','pline':'ANDROID','vn':'5.8.0','over-flow':'new-fly',
        'tn': token ? `Bearer ${token}` : '','sn':sn,'st':session.st,
        'active-time': Math.floor(Math.random()*20000).toString(),
        'content-type':'application/json; charset=UTF-8','user-agent':'okhttp/4.12.0'
    };
}

// Raw TLS — bypass Akamai WAF
function tlsPost(urlStr, body, hdrs) {
    return new Promise(resolve => {
        const u   = new URL(urlStr);
        const str = JSON.stringify(body);
        if (session.cookies.length) hdrs['Cookie'] = session.cookies.join('; ');

        let raw = `POST ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
        for (const [k,v] of Object.entries(hdrs))
            if (!['host','content-length','cookie'].includes(k.toLowerCase()))
                raw += `${k}: ${v}\r\n`;
        if (hdrs['Cookie']) raw += `Cookie: ${hdrs['Cookie']}\r\n`;
        raw += `Content-Length: ${Buffer.byteLength(str)}\r\nConnection: close\r\n\r\n${str}`;

        let sock;
        try {
            sock = tls.connect({
                host: u.hostname, port: 443, servername: u.hostname,
                rejectUnauthorized: false,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256',
                ALPNProtocols: ['http/1.1']
            }, () => sock.write(raw));
        } catch(e) { return resolve({ ok: false, err: e.message }); }

        let buf = Buffer.alloc(0);
        sock.on('data', d => buf = Buffer.concat([buf, d]));
        sock.on('end', () => {
            const s   = buf.toString('binary');
            const idx = s.indexOf('\r\n\r\n');
            if (idx === -1) return resolve({ ok: false, err: 'Bad HTTP' });

            const hPart = s.substring(0, idx);
            let   bPart = buf.subarray(idx + 4);
            const code  = parseInt(hPart.split('\r\n')[0].split(' ')[1], 10);

            const h = {};
            hPart.split('\r\n').slice(1).forEach(l => {
                const p = l.split(':');
                if (p.length > 1) {
                    const key = p[0].trim().toLowerCase();
                    const val = p.slice(1).join(':').trim();
                    h[key] = key === 'set-cookie' ? [...(h[key]||[]), val] : val;
                }
            });

            if (h['st']) session.st = h['st'];
            if (h['set-cookie']) h['set-cookie'].forEach(cs => {
                const m = cs.split(';')[0];
                session.cookies = session.cookies.filter(c => !c.startsWith(m.split('=')[0]+'='));
                session.cookies.push(m);
            });

            if (code >= 400) return resolve({ ok: false, err: `HTTP ${code}` });
            if (h['content-encoding'] === 'gzip') { try { bPart = zlib.gunzipSync(bPart); } catch {} }

            let fs2 = bPart.toString('utf8');
            if (h['transfer-encoding'] === 'chunked') {
                const a = fs2.indexOf('{'), b = fs2.lastIndexOf('}');
                if (a !== -1 && b !== -1) fs2 = fs2.substring(a, b+1);
            }
            try { resolve({ ok: true, data: JSON.parse(fs2) }); }
            catch { resolve({ ok: false, err: 'JSON parse error' }); }
        });
        sock.on('error', e => resolve({ ok: false, err: e.message }));
        sock.setTimeout(TIMEOUT_MS);
        sock.on('timeout', () => { sock.destroy(); resolve({ ok: false, err: 'Timeout' }); });
    });
}

async function apiPost(endpoint, body) {
    const s = await sign(body);
    if (!s) return { ok: false, err: 'Sign gagal' };
    const sep = endpoint.includes('?') ? '&' : '?';
    const r   = await tlsPost(`${endpoint}${sep}timestamp=${s.timestamp}`, body, headers(s.sn, session.token));
    return r.ok && r.data?.data ? { ok: true, data: r.data.data } : { ok: false, err: r.err || 'No data' };
}

// ─── Scrape Catalog ───────────────────────────────────────────────────────────
async function scrapeCatalog() {
    let page = 1, all = [];
    while (true) {
        const r = await apiPost('https://sapi.dramaboxvideo.com/drama-box/he001/theater', {
            newChannelStyle:1, isNeedRank:1, pageNo:page, index:1, channelId:43,
            recSessionId: crypto.randomBytes(32).toString('hex')
        });
        if (r.ok && r.data?.newTheaterList?.records?.length) {
            all.push(...r.data.newTheaterList.records);
            if (page >= (r.data.newTheaterList.pages || 1)) break;
            page++;
            // TANPA DELAY — harus cepat di Vercel
        } else break;
    }
    return all.map(d => ({
        bookId:   d.bookId,
        title:    d.bookName || d.name || 'Unknown',
        cover:    d.cover || d.coverWap || '',
        totalEps: d.chapterCount || d.totalChapter || 0,
        status:   d.serialStatus === 1 ? 'Ongoing' : 'Completed',
        tags:     (d.labelList || []).map(l => l.name).join(', ')
    }));
}

// ─── Scrape Episodes ──────────────────────────────────────────────────────────
async function scrapeEpisodes(bookId) {
    let all = [], cursor = -1, retries = 0;

    while (true) {
        const r = await apiPost('https://sapi.dramaboxvideo.com/drama-box/chapterv2/batch/load', {
            boundaryIndex:0, index: parseInt(cursor),
            currencyPlaySource:'discover_175_rec', needEndRecommend:0,
            currencyPlaySourceName:'首页发现_Untukmu_推荐列表',
            preLoad:false, rid:'', pullCid:'', enterReaderChapterIndex:0,
            loadDirection: cursor === -1 ? 0 : 2,
            startUpKey: crypto.randomUUID(),
            bookId: String(bookId)
        });

        const isEmpty = r.ok && !r.data?.chapterList?.length;

        if (!r.ok || isEmpty) {
            retries++;
            if (retries >= MAX_RETRY) break;
            // Refresh token pada retry genap — TANPA sleep
            if (retries % 2 === 0) { session.ready = false; await ensureToken(); }
            if (cursor !== -1) cursor += 5;
            continue;   // ← TIDAK ada sleep, langsung retry
        }

        retries = 0;
        const fresh = r.data.chapterList.filter(n => !all.some(e => e.chapterId === n.chapterId));
        if (!fresh.length) { cursor += 5; retries++; continue; }

        all.push(...fresh);
        cursor = parseInt(fresh[fresh.length - 1].chapterIndex);
        // TANPA DELAY antar batch — maksimalkan kecepatan
    }

    if (!all.length) return [];
    all.sort((a,b) => a.chapterIndex - b.chapterIndex);

    // Hapus semua field lock/VIP
    return all.map(ep => {
        const o = { ...ep };
        delete o.isCharge; delete o.chargeChapter;
        if (o.cdnList) o.cdnList = o.cdnList.map(cdn => ({
            ...cdn,
            videoPathList: (cdn.videoPathList || []).map(v => { const vv={...v}; delete vv.isVipEquity; return vv; })
        }));
        return o;
    });
}

// ─── Format → URL siap putar ──────────────────────────────────────────────────
function format(raw, base) {
    return raw.map((ep, i) => {
        const title = ep.chapterName || `Episode ${i+1}`;
        const cdn   = ep.cdnList ? (ep.cdnList.find(c => c.isDefault===1) || ep.cdnList[0]) : null;
        const vid   = cdn?.videoPathList ? (cdn.videoPathList.find(v => v.isDefault===1) || cdn.videoPathList[0]) : null;
        const rawUrl = vid?.videoPath || '';
        return {
            title, chapterIndex: ep.chapterIndex,
            playUrl:  rawUrl ? `${base}/api/decrypt?url=${encodeURIComponent(rawUrl)}` : '',
            sources: (cdn?.videoPathList || []).filter(v => v.videoPath).map(v => ({
                quality: v.quality,
                url: `${base}/api/decrypt?url=${encodeURIComponent(v.videoPath)}`
            })),
            thumbnailUrl: ep.chapterImg || ep.spriteSnapshotUrl || ''
        };
    });
}

// ─── Cache helpers ────────────────────────────────────────────────────────────
function paths(bookId) {
    const f = `raw_episodes_${bookId}.json`;
    return { repo: path.resolve(process.cwd(), f), tmp: path.join(TMP, f) };
}

function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }
function writeJson(p, data) { try { fs.writeFileSync(p, JSON.stringify(data)); } catch {} }

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/catalog
app.get('/api/catalog', async (req, res) => {
    // 1. File di repo
    const rp = path.resolve(process.cwd(), 'dramas_catalog.json');
    const re = readJson(rp);
    if (re) return res.json(re);

    // 2. Cache /tmp
    const tp = path.join(TMP, 'dramas_catalog.json');
    const te = readJson(tp);
    if (te) return res.json(te);

    // 3. Auto-scrape
    const ok = await ensureToken();
    if (!ok) return res.status(502).json({ error: 'Gagal inisialisasi token.' });

    const catalog = await scrapeCatalog();
    if (!catalog.length) return res.status(502).json({ error: 'Gagal ambil katalog.' });

    writeJson(tp, catalog);
    res.json(catalog);
});

// GET /api/episodes/:id
app.get('/api/episodes/:id', async (req, res) => {
    const bookId = req.params.id;
    const base   = `${req.protocol}://${req.get('host')}`;
    const { repo, tmp } = paths(bookId);

    // 1. File di repo
    const re = readJson(repo);
    if (re) return res.json(format(re, base));

    // 2. Cache /tmp
    const te = readJson(tmp);
    if (te) return res.json(format(te, base));

    // 3. Auto-scrape (tanpa sleep → muat dalam 10-30 detik)
    const ok = await ensureToken();
    if (!ok) return res.status(502).json({ error: 'Gagal inisialisasi token.' });

    const raw = await scrapeEpisodes(bookId);
    if (!raw.length) return res.status(502).json({
        error: `Gagal ambil episode untuk drama ini. Jalankan node scraper.js secara manual lalu commit file raw_episodes_${bookId}.json ke repo.`
    });

    writeJson(tmp, raw);
    res.json(format(raw, base));
});

// GET /api/decrypt?url=
app.get('/api/decrypt', (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });
    try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }

    const proxyUrl = `https://nb-dramabox-gentoken.vercel.app/decrypt-video?url=${encodeURIComponent(url)}`;
    const req2 = https.get(proxyUrl, r2 => {
        res.status(r2.statusCode || 200);
        ['content-type','content-length','accept-ranges'].forEach(h => {
            if (r2.headers[h]) res.setHeader(h === 'content-type' ? 'Content-Type'
                : h === 'content-length' ? 'Content-Length' : 'Accept-Ranges', r2.headers[h]);
        });
        res.setHeader('Cache-Control', 'public, max-age=3600');
        r2.pipe(res);
    });
    req2.on('error', e => { if (!res.headersSent) res.status(502).json({ error: e.message }); });
    req.on('close', () => req2.destroy());
});

// Fallback → index.html
app.get('*', (req, res) => {
    const p = path.join(__dirname, '../public/index.html');
    fs.existsSync(p) ? res.sendFile(p) : res.status(404).send('Not found');
});

module.exports = app;
