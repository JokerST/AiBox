// 黄果短剧 huangguoai.com
// HTML 刮削源：首頁/分類/搜尋皆為 .hg-card-grid > .hg-drama-card 卡片；
// 排行榜為 .hg-rank-list > .hg-rank-item；詳情頁 .hg-web-detail__ep-grid 給集數；
// 播放頁 <script id="videoInitialData"> 內嵌 JSON，epPlaySrcs[集數] / videoSrc 直接給 m3u8。
//
// ─────────────────────────────────────────────────────────────────────────────
// 圖片解密（方案 B：腳本內解密 + data URI 內嵌）
//
//   站點封面圖為 AES-128-CBC 加密位元組，key/iv 為 UTF-8 16 bytes（不是 hex！）：
//     key = "f5d965df75336270"    ← 16 個 ASCII 字元
//     iv  = "97b60394abc2fbe1"    ← 16 個 ASCII 字元
//
//   ⚠️ 網上註釋常寫成 CryptoJS.enc.Hex.parse('f5d965df75336270')，那是錯的：
//      Hex.parse 會得到 8 bytes，長度不對；必須用 Utf8.parse 才是 16 bytes。
//
//   解密流程：
//     a. raw 為空或 len%16 != 0 → 視為未加密，原樣回傳
//     b. AES-CBC + NoPadding 解密
//     c. 開頭不是圖片簽名（JPEG/PNG/WEBP/GIF）→ 視為未加密，原樣回傳
//     d. 剝離 PKCS7 padding（末字節 pad，1<=pad<=16 且末 pad 字節同值）
//     e. 收尾截斷：JPEG 留到最後 \xff\xd9；PNG 留到 IEND 的 +8 bytes
//     f. Uint8Array → base64 → data:image/xxx;base64,...
//
//   失敗回退：解密失敗則退回原始 URL（剝掉 auth_key），能顯示就顯示，不能顯示就佔位。
// ─────────────────────────────────────────────────────────────────────────────

const UA =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
const SITE = 'https://huangguoai.com'

const HEADERS = {
    'User-Agent': UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Referer: SITE + '/',
}

const TABS = [
    { name: '首页', id: 'home' },
    { name: 'AI成人短剧', id: 'ai-duanju' },
    { name: 'AI成人漫剧', id: 'ai-manju' },
    { name: 'AI换脸', id: 'ai-huanlian' },
    { name: 'AI魔改', id: 'ai-mogai' },
    { name: '排行榜', id: 'ranks/hot' },
]

// ============================== 图片解密 ==============================

// ⚠️ 必须是 Utf8.parse，不是 Hex.parse
const IMG_KEY_STR = 'f5d965df75336270'   // 16 bytes UTF-8
const IMG_IV_STR  = '97b60394abc2fbe1'   // 16 bytes UTF-8

// 检测 CryptoJS 是否可用（不同刮削引擎环境不同）
function getCryptoJS() {
    try {
        if (typeof CryptoJS !== 'undefined' && CryptoJS.AES) return CryptoJS
    } catch (e) {}
    try {
        if (typeof require === 'function') {
            const C = require('crypto-js')
            if (C && C.AES) return C
        }
    } catch (e) {}
    return null
}

// ArrayBuffer / Uint8Array → CryptoJS WordArray
function bytesToWordArray(C, u8) {
    const words = []
    for (let i = 0; i < u8.length; i++) {
        words[i >>> 2] |= u8[i] << (24 - (i % 4) * 8)
    }
    return C.lib.WordArray.create(words, u8.length)
}

// WordArray → Uint8Array
function wordArrayToBytes(C, wa) {
    const hex = C.enc.Hex.stringify(wa)
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16)
    }
    return out
}

// 识别图片类型
function sniffImageType(u8) {
    if (u8.length < 4) return ''
    // JPEG: FF D8
    if (u8[0] === 0xFF && u8[1] === 0xD8) return 'image/jpeg'
    // PNG: 89 50 4E 47
    if (u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4E && u8[3] === 0x47) return 'image/png'
    // GIF: 47 49 46 38
    if (u8[0] === 0x47 && u8[1] === 0x49 && u8[2] === 0x46 && u8[3] === 0x38) return 'image/gif'
    // WEBP: 52 49 46 46 ... 57 45 42 50
    if (u8.length >= 12 &&
        u8[0] === 0x52 && u8[1] === 0x49 && u8[2] === 0x46 && u8[3] === 0x46 &&
        u8[8] === 0x57 && u8[9] === 0x45 && u8[10] === 0x42 && u8[11] === 0x50) {
        return 'image/webp'
    }
    return ''
}

// 剥 PKCS7 padding
function stripPkcs7(u8) {
    if (u8.length === 0) return u8
    const pad = u8[u8.length - 1]
    if (pad < 1 || pad > 16 || pad > u8.length) return u8
    for (let i = u8.length - pad; i < u8.length; i++) {
        if (u8[i] !== pad) return u8
    }
    return u8.slice(0, u8.length - pad)
}

// 截断到图片真正的结尾
function trimToImageEnd(u8, mime) {
    if (mime === 'image/jpeg') {
        // 找最后一个 FF D9
        for (let i = u8.length - 2; i >= 0; i--) {
            if (u8[i] === 0xFF && u8[i + 1] === 0xD9) return u8.slice(0, i + 2)
        }
    } else if (mime === 'image/png') {
        // 找 IEND 块：49 45 4E 44 AE 42 60 82
        const sig = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]
        outer:
        for (let i = u8.length - 8; i >= 0; i--) {
            for (let j = 0; j < 8; j++) {
                if (u8[i + j] !== sig[j]) continue outer
            }
            return u8.slice(0, i + 8)
        }
    }
    return u8
}

// Uint8Array → base64（分块，避免超长字符串栈溢出）
function bytesToBase64(u8) {
    let binary = ''
    const CHUNK = 0x8000
    for (let i = 0; i < u8.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK))
    }
    if (typeof btoa === 'function') return btoa(binary)
    if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
    throw new Error('no base64 encoder')
}

// 主解密函数：raw ArrayBuffer → data URI 字符串（失败返回空串）
function decryptImageToDataURI(raw) {
    if (!raw) return ''
    const u8 = raw instanceof Uint8Array ? raw : new Uint8Array(raw)
    if (u8.length === 0) return ''

    // 长度不是 16 倍数 → 视为未加密
    if (u8.length % 16 !== 0) {
        const mime = sniffImageType(u8)
        if (!mime) return ''
        try {
            return 'data:' + mime + ';base64,' + bytesToBase64(u8)
        } catch (e) { return '' }
    }

    const C = getCryptoJS()
    if (!C) return ''

    let ptBytes
    try {
        const key = C.enc.Utf8.parse(IMG_KEY_STR)
        const iv  = C.enc.Utf8.parse(IMG_IV_STR)
        const cipher = bytesToWordArray(C, u8)
        const pt = C.AES.decrypt(
            { ciphertext: cipher },
            key,
            { iv: iv, mode: C.mode.CBC, padding: C.pad.NoPadding }
        )
        ptBytes = wordArrayToBytes(C, pt)
    } catch (e) {
        return ''
    }

    const mime = sniffImageType(ptBytes)

    // 解密后不是图片 → 源图根本没加密，用原始字节
    if (!mime) {
        const origMime = sniffImageType(u8)
        if (!origMime) return ''
        try {
            return 'data:' + origMime + ';base64,' + bytesToBase64(u8)
        } catch (e) { return '' }
    }

    // 剥 padding + 截断
    let body = stripPkcs7(ptBytes)
    body = trimToImageEnd(body, mime)

    try {
        return 'data:' + mime + ';base64,' + bytesToBase64(body)
    } catch (e) {
        return ''
    }
}

// ============================== 工具 ==============================

function fix(u) {
    if (!u) return ''
    if (u.indexOf('//') === 0) return 'https:' + u
    if (u.indexOf('/') === 0) return SITE + u
    return u
}

// 剥掉 CDN 防盗链 auth_key 等查询参数，得到不过期的稳定直链
function stripAuthKey(u) {
    u = fix(u || '')
    if (u.indexOf('http') === 0 && u.indexOf('?') !== -1) {
        u = u.replace(/\?.*/, '')
    }
    return u
}

function stripTags(s) {
    return String(s || '')
        .replace(/<[^>]*>/g, '')
        .trim()
}

async function fetchHtml(url, referer) {
    const headers = referer ? Object.assign({}, HEADERS, { Referer: referer }) : HEADERS
    const resp = await $fetch.get(url, { headers })
    const data = resp && resp.data
    return typeof data === 'string' ? data : data == null ? '' : JSON.stringify(data)
}

// 抓二进制（图片密文）
async function fetchBinary(url, referer) {
    const headers = referer ? Object.assign({}, HEADERS, { Referer: referer }) : HEADERS
    // 大多数刮削引擎的 $fetch.get 支持 responseType: 'arraybuffer'
    const resp = await $fetch.get(url, {
        headers,
        responseType: 'arraybuffer',
    })
    let data = resp && resp.data
    if (data == null) return null
    if (data instanceof ArrayBuffer) return data
    if (data instanceof Uint8Array) return data.buffer
    // 有些环境返回 Buffer
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    }
    return null
}

// 带并发限制的批量任务
async function withConcurrency(tasks, limit) {
    const results = new Array(tasks.length)
    let idx = 0
    async function worker() {
        while (true) {
            const i = idx++
            if (i >= tasks.length) return
            try {
                results[i] = await tasks[i]()
            } catch (e) {
                results[i] = null
            }
        }
    }
    const workers = []
    for (let i = 0; i < Math.min(limit, tasks.length); i++) {
        workers.push(worker())
    }
    await Promise.all(workers)
    return results
}

// ============================== 卡片解析 ==============================

function gridSlices(html, allGrids) {
    const re = /<div\s+class="[^"]*\bhg-card-grid\b[^"]*"[^>]*>/g
    const starts = []
    let m
    while ((m = re.exec(html)) !== null) starts.push(m.index + m[0].length)
    if (!starts.length) return []
    const slices = []
    const n = allGrids ? starts.length : Math.min(1, starts.length)
    for (let i = 0; i < n; i++) {
        const to = i + 1 < starts.length ? starts[i + 1] : html.length
        slices.push(html.slice(starts[i], to))
    }
    return slices
}

function cardBlocks(slice) {
    const re = /<div\s+class="[^"]*\bhg-drama-card\b[^"]*"[^>]*>/g
    const starts = []
    let m
    while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length)
    const blocks = []
    for (let i = 0; i < starts.length; i++) {
        const to = i + 1 < starts.length ? starts[i + 1] : slice.length
        blocks.push(slice.slice(starts[i], to))
    }
    return blocks
}

function parseCardBlock(block) {
    const a = block.match(/href="[^"]*\/detail\/(\d+)\/[^"]*"/)
    if (!a) return null
    const vid = a[1]
    const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/)
    let title = ''
    const t = block.match(/hg-drama-card__title[^>]*>([\s\S]*?)<\/a>/)
    if (t) title = stripTags(t[1])
    if (!title) {
        const tt = block.match(/<a[^>]+href="[^"]*\/detail\/\d+\/"[^>]*>([\s\S]*?)<\/a>/)
        if (tt) title = stripTags(tt[1])
    }
    if (!title) return null
    const ep = block.match(/hg-drama-card__episode[^>]*>([\s\S]*?)<\/span>/)
    const score = block.match(/hg-drama-card__score[^>]*>([\s\S]*?)<\/span>/)
    const rem = ep ? ep[1].trim() : ''
    const sc = score ? score[1].trim() : ''
    let remarks = ''
    if (rem && sc) remarks = rem + ' · ' + sc
    else remarks = rem || sc
    return {
        vod_id: vid,
        vod_name: title,
        vod_pic: imgM ? fix(imgM[1]) : '',   // ← 保留原始带 auth_key 的 URL，供后续解密
        vod_remarks: remarks,
        ext: { id: vid },
    }
}

// 解析卡片 + 异步解密图片
async function parseGridCards(html, allGrids) {
    if (!html) return []
    const list = []
    const seen = {}
    const slices = gridSlices(html, allGrids)

    // 先同步解析出所有 item
    for (const slice of slices) {
        for (const block of cardBlocks(slice)) {
            try {
                const item = parseCardBlock(block)
                if (!item || seen[item.vod_id]) continue
                seen[item.vod_id] = true
                list.push(item)
            } catch (e) {}
        }
    }

    // 再并发解密图片（限制并发，避免打爆 CDN）
    await withConcurrency(list.map((item) => async () => {
        if (!item.vod_pic) return
        try {
            const raw = await fetchBinary(item.vod_pic, SITE + '/')
            const dataUri = decryptImageToDataURI(raw)
            if (dataUri) {
                item.vod_pic = dataUri
            } else {
                // 解密失败：回退到剥掉 auth_key 的 URL（多半还是显示不出来，但聊胜于无）
                item.vod_pic = stripAuthKey(item.vod_pic)
            }
        } catch (e) {
            item.vod_pic = stripAuthKey(item.vod_pic)
        }
    }), 6)  // 并发上限 6

    return list
}

// ============================== 排行榜解析 ==============================

async function parseRanks(html) {
    if (!html) return []
    const listM = html.match(/<div\s+class="[^"]*\bhg-rank-list\b[^"]*"[^>]*>/)
    const from = listM ? listM.index + listM[0].length : 0
    const slice = html.slice(from)
    const re = /<div\s+class="[^"]*\bhg-rank-item\b[^"]*"[^>]*>/g
    const starts = []
    let m
    while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length)
    const list = []
    const seen = {}
    for (let i = 0; i < starts.length; i++) {
        const to = i + 1 < starts.length ? starts[i + 1] : slice.length
        const block = slice.slice(starts[i], to)
        try {
            const a = block.match(/href="[^"]*\/detail\/(\d+)\/[^"]*"/)
            if (!a || seen[a[1]]) continue
            seen[a[1]] = true
            const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/)
            let title = ''
            const t = block.match(/hg-rank-item__title[^>]*>([\s\S]*?)<\/h2>/)
            if (t) title = stripTags(t[1])
            if (!title) {
                const tt = block.match(/<a[^>]+href="[^"]*\/detail\/\d+\/"[^>]*>([\s\S]*?)<\/a>/)
                if (tt) title = stripTags(tt[1])
            }
            if (!title) continue
            const tags = block.match(/hg-rank-item__tags[^>]*>([\s\S]*?)<\/div>/)
            list.push({
                vod_id: a[1],
                vod_name: title,
                vod_pic: imgM ? fix(imgM[1]) : '',
                vod_remarks: tags ? stripTags(tags[1]) : '',
                ext: { id: a[1] },
            })
        } catch (e) {}
    }

    // 并发解密
    await withConcurrency(list.map((item) => async () => {
        if (!item.vod_pic) return
        try {
            const raw = await fetchBinary(item.vod_pic, SITE + '/')
            const dataUri = decryptImageToDataURI(raw)
            item.vod_pic = dataUri || stripAuthKey(item.vod_pic)
        } catch (e) {
            item.vod_pic = stripAuthKey(item.vod_pic)
        }
    }), 6)

    return list
}

// ============================== 介面 ==============================

async function getLocalInfo() {
    return jsonify({ ver: 1, name: '黄果短剧', api: 'csp_huangguo', type: 3 })
}

async function getConfig() {
    return jsonify({
        ver: 1,
        title: '黄果短剧',
        site: SITE,
        tabs: TABS.map((t) => ({ name: t.name, ext: { id: t.id } })),
    })
}

async function getCards(ext) {
    ext = argsify(ext)
    const id = String(ext.id || 'home').replace(/^\//, '')
    const page = Math.max(1, parseInt(ext.page) || 1)
    try {
        if (id === 'home') {
            const html = await fetchHtml(SITE + '/')
            return jsonify({ list: await parseGridCards(html, true), page: page })
        }
        const url = SITE + '/' + id + '/' + (page > 1 ? page + '/' : '')
        const html = await fetchHtml(url)
        if (id.indexOf('rank') !== -1) {
            return jsonify({ list: await parseRanks(html), page: page })
        }
        return jsonify({ list: await parseGridCards(html, false), page: page })
    } catch (e) {
        console.error('getCards error:', e)
        return jsonify({ list: [], page: page })
    }
}

async function getTracks(ext) {
    ext = argsify(ext)
    const id = ext.id || ''
    if (!id) return jsonify({ list: [] })
    try {
        const html = await fetchHtml(SITE + '/detail/' + id + '/')
        const tracks = []
        const gridM = html.match(/<div\s+class="[^"]*\bhg-web-detail__ep-grid\b[^"]*"[^>]*>([\s\S]*?)<\/div>/)
        if (gridM) {
            const are = /<a\b[^>]*>[\s\S]*?<\/a>/g
            let m
            while ((m = are.exec(gridM[1])) !== null) {
                const tag = m[0]
                const hrefM = tag.match(/href="([^"]+)"/)
                if (!hrefM) continue
                const href = hrefM[1]
                const eidM = tag.match(/data-ep-id="([^"]*)"/)
                const eid = eidM ? eidM[1] : ''
                const name = eid ? '第' + eid + '集' : stripTags(tag)
                tracks.push({ name: name, ext: { url: fix(href), ep: eid } })
            }
        }
        if (!tracks.length) {
            const playM = html.match(/<a\b[^>]*class="[^"]*\bhg-web-detail__play\b[^"]*"[^>]*href="([^"]+)"/)
            if (playM) {
                tracks.push({ name: '第1集', ext: { url: fix(playM[1]), ep: '' } })
            }
        }
        if (!tracks.length) return jsonify({ list: [] })
        return jsonify({ list: [{ title: '黄果短剧', tracks: tracks }] })
    } catch (e) {
        console.error('getTracks error:', e)
        return jsonify({ list: [] })
    }
}

async function getPlayinfo(ext) {
    ext = argsify(ext)
    const url = ext.url || ''
    const ep = String(ext.ep || '1')
    if (!url) return jsonify({ urls: [] })
    try {
        const html = await fetchHtml(url, SITE)
        let play = ''
        const m = html.match(/id="videoInitialData"[^>]*>([\s\S]*?)<\/script>/)
        if (m) {
            try {
                const data = JSON.parse(m[1])
                const srcs = (data && data.epPlaySrcs) || {}
                play = srcs[ep] || (data && data.videoSrc) || ''
            } catch (e) {}
        }
        if (play) {
            play = play.replace(/\\u0026/g, '&')
            if (play.indexOf('http') !== 0) {
                const mm = play.match(/(https?:\/\/[^\s"']+)/)
                play = mm ? mm[1] : ''
            }
        }
        if (!play) return jsonify({ urls: [] })
        return jsonify({
            urls: [play],
            headers: [{ 'User-Agent': UA, Referer: SITE + '/' }],
        })
    } catch (e) {
        console.error('getPlayinfo error:', e)
        return jsonify({ urls: [] })
    }
}

async function search(ext) {
    ext = argsify(ext)
    const kw = String(ext.text || ext.wd || '').trim()
    if (!kw) return jsonify({ list: [], page: 1 })
    try {
        const html = await fetchHtml(SITE + '/search/video/' + encodeURIComponent(kw) + '/')
        return jsonify({ list: await parseGridCards(html, false), page: 1 })
    } catch (e) {
        console.error('search error:', e)
        return jsonify({ list: [], page: 1 })
    }
}