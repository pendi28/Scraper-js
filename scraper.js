/**
 * DramaBox Auto Scraper
 * Diadaptasi dari: https://github.com/giienew/dramabox-scraper
 *
 * Cara pakai di Termux / Node.js:
 *   npm install
 *   node scraper.js
 *
 * Output:
 *   dramas_catalog.json          → daftar semua drama
 *   raw_episodes_<bookId>.json   → semua episode (semua terbuka, siap diputar)
 */

const readline = require('readline');
const fs       = require('fs');
const tls      = require('tls');
const crypto   = require('crypto');
const zlib     = require('zlib');
const axios    = require('axios');

// ─── Config ───────────────────────────────────────────────────────────────────
const API_BASE   = 'https://nb-dramabox-gentoken.vercel.app';
const TIMEOUT_MS = 15000;
const MAX_RETRIES = 5;

// ─── Session ──────────────────────────────────────────────────────────────────
const session = {
    token: '', deviceid: '', androidid: '',
    instanceid: crypto.randomBytes(16).toString('hex'),
    afid: `${Date.now()}-${Math.floor(Math.random() * 9999999999999999)}`,
    ins: Date.now().toString(),
    st: 'cK4n10B_0tTQBrxFyyBWnOKD',
    cookies: []
};

// ─── Warna ────────────────────────────────────────────────────────────────────
const c = {
    rst:'\x1b[0m', bld:'\x1b[1m', dim:'\x1b[2m',
    red:'\x1b[31m', grn:'\x1b[32m', ylw:'\x1b[33m',
    blu:'\x1b[34m', cyn:'\x1b[36m'
};

// ─── Utils ────────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

function getLocalTime() {
    const now = new Date();
    const bt  = new Date(now.getTime() + 7 * 3600000);
    const p   = n => n.toString().padStart(2, '0');
    return `${bt.getUTCFullYear()}-${p(bt.getUTCMonth()+1)}-${p(bt.getUTCDate())} ` +
           `${p(bt.getUTCHours())}:${p(bt.getUTCMinutes())}:${p(bt.getUTCSeconds())}.` +
           `${bt.getUTCMilliseconds().toString().padStart(3,'0')} +0700`;
}

function saveJson(filename, data) {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
    const count = Array.isArray(data) ? data.length : Object.keys(data).length;
    console.log(`${c.grn}[+]${c.rst} Tersimpan: ${c.bld}${filename}${c.rst} (${count} item)`);
}

const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(r => rl.question(`${c.ylw}?${c.rst} ${q}`, r));

// ─── Token & Tanda Tangan ─────────────────────────────────────────────────────
async function generateToken() {
    process.stdout.write(`${c.cyn}[*]${c.rst} Inisialisasi session... `);
    try {
        const res = await axios.get(`${API_BASE}/generate-token`, { timeout: TIMEOUT_MS });
        if (res.data?.status && res.data?.data) {
            Object.assign(session, {
                token: res.data.data.sn,
                deviceid: res.data.data.device_id,
                androidid: res.data.data.android_id,
                cookies: []
            });
            console.log(`${c.grn}OK${c.rst}`);
            return true;
        }
        console.log(`${c.red}GAGAL${c.rst}`); return false;
    } catch (e) {
        console.log(`${c.red}ERROR: ${e.message}${c.rst}`); return false;
    }
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
        'accept-encoding':'gzip','version':'580',
        'package-name':'com.storymatrix.drama','p':'63',
        'cid':'DRA1000042','apn':'2','country-code':'ID',
        'mchid':'DRA1000042','tz':'-420','language':'in',
        'mcc':'510','locale':'in_ID','is_root':'0',
        'device-id': session.deviceid,'nchid':'DRA1000042',
        'instanceid': session.instanceid,'md':'Redmi Note 5',
        'store-source':'store_google','mf':'XIAOMI','device-score':'60',
        'local-time': getLocalTime(),'time-zone':'+0700','brand':'Xiaomi',
        'lat':'0','is_emulator':'0','current-language':'in','ov':'10',
        'afid': session.afid,'android-id': session.androidid,
        'srn':'1080x2160','ins': session.ins,'is_vpn':'1',
        'build':'Build/QQ3A.200805.001','pline':'ANDROID','vn':'5.8.0',
        'over-flow':'new-fly','tn': token ? `Bearer ${token}` : '',
        'sn': sn,'st': session.st,
        'active-time': Math.floor(Math.random()*20000).toString(),
        'content-type':'application/json; charset=UTF-8',
        'user-agent':'okhttp/4.12.0'
    };
}

// ─── Raw TLS Request (bypass Akamai WAF) ──────────────────────────────────────
function wRequest(urlStr, bodyObj, headers) {
    return new Promise(resolve => {
        const u   = new URL(urlStr);
        const str = JSON.stringify(bodyObj);
        if (session.cookies.length) headers['Cookie'] = session.cookies.join('; ');

        let raw = `POST ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
        for (const [k,v] of Object.entries(headers))
            if (!['host','content-length','cookie'].includes(k.toLowerCase()))
                raw += `${k}: ${v}\r\n`;
        if (headers['Cookie']) raw += `Cookie: ${headers['Cookie']}\r\n`;
        raw += `Content-Length: ${Buffer.byteLength(str)}\r\nConnection: close\r\n\r\n${str}`;

        const sock = tls.connect({
            host: u.hostname, port: 443, servername: u.hostname,
            rejectUnauthorized: false,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
            ALPNProtocols: ['http/1.1']
        }, () => sock.write(raw));

        let buf = Buffer.alloc(0);
        sock.on('data', d => buf = Buffer.concat([buf, d]));
        sock.on('end', () => {
            const s   = buf.toString('binary');
            const idx = s.indexOf('\r\n\r\n');
            if (idx === -1) return resolve({ success: false, error: 'Invalid HTTP' });

            const hPart = s.substring(0, idx);
            let body    = buf.subarray(idx + 4);
            const code  = parseInt(hPart.split('\r\n')[0].split(' ')[1], 10);

            const h = {};
            hPart.split('\r\n').slice(1).forEach(line => {
                const p = line.split(':');
                if (p.length > 1) {
                    const key = p[0].trim().toLowerCase();
                    const val = p.slice(1).join(':').trim();
                    h[key] = key === 'set-cookie' ? [...(h[key]||[]), val] : val;
                }
            });

            if (h['st']) session.st = h['st'];
            if (h['set-cookie']) h['set-cookie'].forEach(cs => {
                const main = cs.split(';')[0];
                session.cookies = session.cookies.filter(c => !c.startsWith(main.split('=')[0]+'='));
                session.cookies.push(main);
            });

            if (code >= 400) return resolve({ success: false, error: `Blocked (${code})` });

            if (h['content-encoding'] === 'gzip') {
                try { body = zlib.gunzipSync(body); } catch {}
            }
            let finalStr = body.toString('utf8');
            if (h['transfer-encoding'] === 'chunked') {
                const a = finalStr.indexOf('{'), b = finalStr.lastIndexOf('}');
                if (a !== -1 && b !== -1) finalStr = finalStr.substring(a, b+1);
            }
            try { resolve({ success: true, data: JSON.parse(finalStr) }); }
            catch { resolve({ success: false, error: 'JSON Parse Error' }); }
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

// ─── [1] Ambil Daftar Drama (Katalog) ─────────────────────────────────────────
async function scrapeCatalog() {
    console.log(`\n${c.cyn}${c.bld}--- [ AMBIL KATALOG DRAMA ] ---${c.rst}`);
    let page = 1, all = [];

    while (true) {
        process.stdout.write(`\r${c.blu}[~]${c.rst} Halaman ${page}... `);

        const body = {
            newChannelStyle: 1, isNeedRank: 1, pageNo: page,
            index: 1, channelId: 43,
            recSessionId: crypto.randomBytes(32).toString('hex')
        };
        const res = await postData('https://sapi.dramaboxvideo.com/drama-box/he001/theater', body);

        if (res.success && res.data?.newTheaterList?.records?.length > 0) {
            const records = res.data.newTheaterList.records;
            all.push(...records);
            console.log(`${c.grn}OK${c.rst} (${all.length} total)`);
            if (page >= (res.data.newTheaterList.pages || 1)) break;
            page++;
            await sleep(800 + Math.random() * 500);
        } else {
            console.log(`${c.dim}Selesai.${c.rst}`);
            break;
        }
    }

    // Format katalog: hanya field penting
    const catalog = all.map(item => ({
        bookId:    item.bookId,
        title:     item.bookName || item.name || 'Unknown',
        cover:     item.cover || item.coverWap || '',
        totalEps:  item.chapterCount || item.totalChapter || 0,
        status:    item.serialStatus === 1 ? 'Ongoing' : 'Completed',
        tags:      (item.labelList || []).map(l => l.name).join(', ')
    }));

    if (catalog.length > 0) {
        saveJson('dramas_catalog.json', catalog);
    } else {
        console.log(`${c.red}[-]${c.rst} Tidak ada drama ditemukan.`);
    }
    return catalog;
}

// ─── [2] Ambil Semua Episode (Tanpa Filter Lock) ──────────────────────────────
async function scrapeEpisodes(bookId) {
    console.log(`\n${c.cyn}${c.bld}--- [ AMBIL EPISODE: ${bookId} ] ---${c.rst}`);

    let all = [], cursor = -1, batch = 1, retries = 0;

    while (true) {
        process.stdout.write(`\r${c.blu}[~]${c.rst} Batch #${batch} (cursor: ${cursor})... `);

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

        const res = await postData(
            'https://sapi.dramaboxvideo.com/drama-box/chapterv2/batch/load', body
        );

        const isEmpty = res.success && !res.data?.chapterList?.length;

        if (!res.success || isEmpty) {
            retries++;
            console.log(`\n${c.ylw}[!]${c.rst} Kosong/Blocked — percobaan ${retries}/${MAX_RETRIES}`);
            if (retries >= MAX_RETRIES) { console.log(`${c.red}[-]${c.rst} Selesai.`); break; }
            if (retries === 2 || retries === 4) {
                process.stdout.write(`${c.cyn}[*]${c.rst} Refresh token... `);
                await generateToken();
            }
            if (cursor !== -1) cursor += 5;
            await sleep(2000 + Math.random() * 2000);
            continue;
        }

        retries = 0;
        const newEps = res.data.chapterList.filter(n => !all.some(e => e.chapterId === n.chapterId));

        if (!newEps.length) {
            cursor += 5; retries++;
        } else {
            all.push(...newEps);
            cursor = parseInt(newEps[newEps.length - 1].chapterIndex);
            console.log(`${c.grn}OK${c.rst} — total: ${c.bld}${all.length}${c.rst}`);
        }
        batch++;
        await sleep(900 + Math.random() * 700);
    }

    if (all.length > 0) {
        all.sort((a, b) => a.chapterIndex - b.chapterIndex);
        // Hapus field isCharge/isVip — semua episode dianggap terbuka
        const clean = all.map(ep => {
            const out = { ...ep };
            delete out.isCharge;
            delete out.chargeChapter;
            // Hapus flag VIP dari setiap video dalam cdnList
            if (out.cdnList) {
                out.cdnList = out.cdnList.map(cdn => ({
                    ...cdn,
                    videoPathList: (cdn.videoPathList || []).map(v => {
                        const vClean = { ...v };
                        delete vClean.isVipEquity;
                        return vClean;
                    })
                }));
            }
            return out;
        });
        saveJson(`raw_episodes_${bookId}.json`, clean);
        return clean;
    } else {
        console.log(`${c.red}[-]${c.rst} Tidak ada episode yang berhasil diambil.`);
        return [];
    }
}

// ─── [3] Otomatis: Katalog + Semua Episode ────────────────────────────────────
async function scrapeAll() {
    console.log(`\n${c.cyn}${c.bld}=== MODE OTOMATIS PENUH ===${c.rst}`);
    console.log(`${c.dim}Akan ambil katalog drama, lalu semua episode tiap drama.${c.rst}\n`);

    const catalog = await scrapeCatalog();
    if (!catalog.length) {
        console.log(`${c.red}[-]${c.rst} Katalog kosong, berhenti.`);
        return;
    }

    console.log(`\n${c.grn}[+]${c.rst} Ditemukan ${c.bld}${catalog.length}${c.rst} drama.`);

    const batasStr = await ask(`Ambil episode untuk berapa drama? (kosong = semua ${catalog.length}): `);
    const batas = parseInt(batasStr) || catalog.length;
    const target = catalog.slice(0, batas);

    console.log(`\n${c.cyn}[*]${c.rst} Mulai scrape ${target.length} drama...\n`);

    for (let i = 0; i < target.length; i++) {
        const drama = target[i];
        console.log(`\n${c.bld}[${i+1}/${target.length}]${c.rst} ${drama.title} (ID: ${drama.bookId})`);

        // Skip jika sudah ada
        if (fs.existsSync(`raw_episodes_${drama.bookId}.json`)) {
            console.log(`${c.dim}  → File sudah ada, skip.${c.rst}`);
            continue;
        }

        await scrapeEpisodes(drama.bookId);

        // Jeda antar drama agar tidak kena rate-limit
        if (i < target.length - 1) {
            console.log(`${c.dim}  → Jeda 3 detik...${c.rst}`);
            await sleep(3000);
        }
    }

    console.log(`\n${c.grn}${c.bld}✓ Selesai! Semua file JSON sudah tersimpan.${c.rst}`);
    console.log(`${c.dim}Upload semua raw_episodes_*.json dan dramas_catalog.json ke root repo GitHub kamu, lalu deploy.${c.rst}\n`);
}

// ─── Main Menu ────────────────────────────────────────────────────────────────
async function main() {
    console.log(`\n${c.cyn}${c.bld}`);
    console.log('╔══════════════════════════════════╗');
    console.log('║   DramaBox Auto Scraper v2.0     ║');
    console.log('║   Semua Episode Terbuka (No Lock)║');
    console.log('╚══════════════════════════════════╝');
    console.log(c.rst);

    const ok = await generateToken();
    if (!ok) {
        console.log(`${c.red}[-]${c.rst} Gagal inisialisasi. Coba lagi.`);
        rl.close(); return;
    }

    while (true) {
        console.log(`\n${c.bld}=== MENU ===${c.rst}`);
        console.log(`${c.cyn}[1]${c.rst} Ambil DAFTAR DRAMA → dramas_catalog.json`);
        console.log(`${c.cyn}[2]${c.rst} Ambil EPISODE satu drama → raw_episodes_<id>.json`);
        console.log(`${c.cyn}[3]${c.rst} ${c.bld}OTOMATIS PENUH${c.rst} — ambil katalog + semua episodenya`);
        console.log(`${c.red}[0]${c.rst} Keluar\n`);

        const pilihan = (await ask('Pilih menu: ')).trim();

        if (pilihan === '0') {
            console.log('Sampai jumpa!');
            rl.close(); return;

        } else if (pilihan === '1') {
            await scrapeCatalog();

        } else if (pilihan === '2') {
            const bookId = (await ask('Masukkan Book ID (contoh: 42000011213): ')).trim();
            if (!bookId || isNaN(bookId)) {
                console.log(`${c.red}[-]${c.rst} Book ID tidak valid.`);
                continue;
            }
            await scrapeEpisodes(bookId);

        } else if (pilihan === '3') {
            await scrapeAll();

        } else {
            console.log(`${c.ylw}[!]${c.rst} Pilihan tidak valid.`);
        }
    }
}

main();
