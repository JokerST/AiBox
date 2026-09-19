/* ============================================================
 * 黄果短剧 huangguoai.com —— 纯前端刮削 + 封面解密
 *
 * 封面是 AES-128-CBC 加密字节，key/iv 是 UTF-8 的 16 字节：
 *   key = "f5d965df75336270"
 *   iv  = "97b60394abc2fbe1"
 * ⚠️ 必须用 CryptoJS.enc.Utf8.parse，不能用 Hex.parse（只有 8 字节，长度不对）。
 *
 * 解密流程：
 *   1. 长度非 16 倍数 → 视为未加密，原样返回
 *   2. AES-CBC + NoPadding 解密
 *   3. 解密后开头不是图片签名 → 视为未加密，回退原始字节
 *   4. 剥 PKCS7 padding
 *   5. 截断到图片真正结尾（JPEG 到 FFD9，PNG 到 IEND+8）
 *   6. 转 base64 → data:image/...;base64,...
 *   7. 写回 img.src，移除 data-src
 *
 * 失败回退：解密失败 → 用剥掉 auth_key 的 URL；再失败 → 保留占位图。
 * ============================================================ */

(function () {
  'use strict';

  // ── 配置 ──────────────────────────────────────────────
  const UA =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  const SITE = 'https://huangguoai.com';

  const HEADERS = {
    'User-Agent': UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Referer: SITE + '/',
  };

  const TABS = [
    { name: '首页', id: 'home' },
    { name: 'AI成人短剧', id: 'ai-duanju' },
    { name: 'AI成人漫剧', id: 'ai-manju' },
    { name: 'AI换脸', id: 'ai-huanlian' },
    { name: 'AI魔改', id: 'ai-mogai' },
    { name: '排行榜', id: 'ranks/hot' },
  ];

  const CONCURRENCY = 6;                  // 解密并发上限

  // ── 图片解密 ──────────────────────────────────────────
  const IMG_KEY_STR = 'f5d965df75336270'; // 16 字节 UTF-8
  const IMG_IV_STR  = '97b60394abc2fbe1'; // 16 字节 UTF-8

  function bytesToWordArray(u8) {
    const words = [];
    for (let i = 0; i < u8.length; i++) words[i >>> 2] |= u8[i] << (24 - (i % 4) * 8);
    return CryptoJS.lib.WordArray.create(words, u8.length);
  }

  function wordArrayToBytes(wa) {
    const hex = CryptoJS.enc.Hex.stringify(wa);
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function sniffImageType(u8) {
    if (u8.length < 4) return '';
    if (u8[0] === 0xFF && u8[1] === 0xD8) return 'image/jpeg';
    if (u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4E && u8[3] === 0x47) return 'image/png';
    if (u8[0] === 0x47 && u8[1] === 0x49 && u8[2] === 0x46 && u8[3] === 0x38) return 'image/gif';
    if (u8.length >= 12 &&
        u8[0] === 0x52 && u8[1] === 0x49 && u8[2] === 0x46 && u8[3] === 0x46 &&
        u8[8] === 0x57 && u8[9] === 0x45 && u8[10] === 0x42 && u8[11] === 0x50) return 'image/webp';
    return '';
  }

  function stripPkcs7(u8) {
    if (!u8.length) return u8;
    const pad = u8[u8.length - 1];
    if (pad < 1 || pad > 16 || pad > u8.length) return u8;
    for (let i = u8.length - pad; i < u8.length; i++) if (u8[i] !== pad) return u8;
    return u8.slice(0, u8.length - pad);
  }

  function trimToImageEnd(u8, mime) {
    if (mime === 'image/jpeg') {
      for (let i = u8.length - 2; i >= 0; i--) {
        if (u8[i] === 0xFF && u8[i + 1] === 0xD9) return u8.slice(0, i + 2);
      }
    } else if (mime === 'image/png') {
      const sig = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]; // IEND
      outer:
      for (let i = u8.length - 8; i >= 0; i--) {
        for (let j = 0; j < 8; j++) if (u8[i + j] !== sig[j]) continue outer;
        return u8.slice(0, i + 8);
      }
    }
    return u8;
  }

  function bytesToBase64(u8) {
    let binary = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < u8.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    }
    return btoa(binary);
  }

  function decryptImageToDataURI(raw) {
    if (!raw) return '';
    const u8 = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    if (!u8.length) return '';

    // 长度非 16 倍数 → 视为未加密
    if (u8.length % 16 !== 0) {
      const mime = sniffImageType(u8);
      return mime ? 'data:' + mime + ';base64,' + bytesToBase64(u8) : '';
    }

    let ptBytes;
    try {
      const key = CryptoJS.enc.Utf8.parse(IMG_KEY_STR);
      const iv  = CryptoJS.enc.Utf8.parse(IMG_IV_STR);
      const pt = CryptoJS.AES.decrypt(
        { ciphertext: bytesToWordArray(u8) },
        key,
        { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }
      );
      ptBytes = wordArrayToBytes(pt);
    } catch (e) { return ''; }

    const mime = sniffImageType(ptBytes);

    // 解密后不是图片 → 源图未加密，用原始字节
    if (!mime) {
      const origMime = sniffImageType(u8);
      return origMime ? 'data:' + origMime + ';base64,' + bytesToBase64(u8) : '';
    }

    let body = stripPkcs7(ptBytes);
    body = trimToImageEnd(body, mime);
    return 'data:' + mime + ';base64,' + bytesToBase64(body);
  }

  // ── 日志 ──────────────────────────────────────────────
  function log(msg) { console.log('[hg]', msg); }

  // ── 工具（保持原函数名） ──────────────────────────────
  function fix(u) {
    if (!u) return '';
    if (u.indexOf('//') === 0) return 'https:' + u;
    if (u.indexOf('/') === 0) return SITE + u;
    return u;
  }

  // 剥掉 CDN 防盗链 auth_key 等查询参数
  function imgSrc(u) {
    u = fix(u || '');
    if (u.indexOf('http') === 0 && u.indexOf('?') !== -1) {
      u = u.replace(/\?.*/, '');
    }
    return u;
  }

  function stripTags(s) {
    return String(s || '').replace(/<[^>]*>/g, '').trim();
  }

  // 浏览器原生 fetch 替代 $fetch.get
  async function fetchHtml(url, referer) {
    const headers = referer ? Object.assign({}, HEADERS, { Referer: referer }) : HEADERS;
    const resp = await fetch(url, { headers });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.text();
  }

  // 抓二进制（图片密文）
  async function fetchBinary(url, referer) {
    const headers = referer ? Object.assign({}, HEADERS, { Referer: referer }) : HEADERS;
    const resp = await fetch(url, { headers });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.arrayBuffer();
  }

  // 浏览器原生替代 jsonify
  function jsonify(obj) { return obj; }

  // 浏览器原生替代 argsify
  function argsify(x) {
    if (typeof x === 'string') {
      try { return JSON.parse(x); } catch (e) { return {}; }
    }
    return x || {};
  }

  // 并发控制器
  async function withConcurrency(tasks, limit) {
    const results = new Array(tasks.length);
    let idx = 0;
    async function worker() {
      while (true) {
        const i = idx++;
        if (i >= tasks.length) return;
        try { results[i] = await tasks[i](); } catch (e) { results[i] = null; }
      }
    }
    const workers = [];
    for (let i = 0; i < Math.min(limit, tasks.length); i++) workers.push(worker());
    await Promise.all(workers);
    return results;
  }

  // ── 卡片解析（保持原函数名） ──────────────────────────
  function gridSlices(html, allGrids) {
    const re = /<div\s+class="[^"]*\bhg-card-grid\b[^"]*"[^>]*>/g;
    const starts = [];
    let m;
    while ((m = re.exec(html)) !== null) starts.push(m.index + m[0].length);
    if (!starts.length) return [];
    const slices = [];
    const n = allGrids ? starts.length : Math.min(1, starts.length);
    for (let i = 0; i < n; i++) {
      const to = i + 1 < starts.length ? starts[i + 1] : html.length;
      slices.push(html.slice(starts[i], to));
    }
    return slices;
  }

  function cardBlocks(slice) {
    const re = /<div\s+class="[^"]*\bhg-drama-card\b[^"]*"[^>]*>/g;
    const starts = [];
    let m;
    while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length);
    const blocks = [];
    for (let i = 0; i < starts.length; i++) {
      const to = i + 1 < starts.length ? starts[i + 1] : slice.length;
      blocks.push(slice.slice(starts[i], to));
    }
    return blocks;
  }

  function parseCardBlock(block) {
    const a = block.match(/href="[^"]*\/detail\/(\d+)\/[^"]*"/);
    if (!a) return null;
    const vid = a[1];
    const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/);
    let title = '';
    const t = block.match(/hg-drama-card__title[^>]*>([\s\S]*?)<\/a>/);
    if (t) title = stripTags(t[1]);
    if (!title) {
      const tt = block.match(/<a[^>]+href="[^"]*\/detail\/\d+\/"[^>]*>([\s\S]*?)<\/a>/);
      if (tt) title = stripTags(tt[1]);
    }
    if (!title) return null;
    const ep = block.match(/hg-drama-card__episode[^>]*>([\s\S]*?)<\/span>/);
    const score = block.match(/hg-drama-card__score[^>]*>([\s\S]*?)<\/span>/);
    const rem = ep ? ep[1].trim() : '';
    const sc = score ? score[1].trim() : '';
    let remarks = '';
    if (rem && sc) remarks = rem + ' · ' + sc;
    else remarks = rem || sc;
    return {
      vod_id: vid,
      vod_name: title,
      vod_pic: imgM ? fix(imgM[1]) : '',   // 保留原始带 auth_key 的 URL
      vod_remarks: remarks,
      ext: { id: vid },
    };
  }

  // 解析 + 并发解密
  async function parseGridCards(html, allGrids) {
    if (!html) return [];
    const list = [];
    const seen = {};
    const slices = gridSlices(html, allGrids);
    for (const slice of slices) {
      for (const block of cardBlocks(slice)) {
        try {
          const item = parseCardBlock(block);
          if (!item || seen[item.vod_id]) continue;
          seen[item.vod_id] = true;
          list.push(item);
        } catch (e) {}
      }
    }
    await withConcurrency(list.map((item) => async () => {
      if (!item.vod_pic) return;
      try {
        const raw = await fetchBinary(item.vod_pic, SITE + '/');
        const dataUri = decryptImageToDataURI(raw);
        item.vod_pic = dataUri || imgSrc(item.vod_pic);
      } catch (e) {
        item.vod_pic = imgSrc(item.vod_pic);
      }
    }), CONCURRENCY);
    return list;
  }

  // ── 排行榜解析（保持原函数名） ────────────────────────
  async function parseRanks(html) {
    if (!html) return [];
    const listM = html.match(/<div\s+class="[^"]*\bhg-rank-list\b[^"]*"[^>]*>/);
    const from = listM ? listM.index + listM[0].length : 0;
    const slice = html.slice(from);
    const re = /<div\s+class="[^"]*\bhg-rank-item\b[^"]*"[^>]*>/g;
    const starts = [];
    let m;
    while ((m = re.exec(slice)) !== null) starts.push(m.index + m[0].length);
    const list = [];
    const seen = {};
    for (let i = 0; i < starts.length; i++) {
      const to = i + 1 < starts.length ? starts[i + 1] : slice.length;
      const block = slice.slice(starts[i], to);
      try {
        const a = block.match(/href="[^"]*\/detail\/(\d+)\/[^"]*"/);
        if (!a || seen[a[1]]) continue;
        seen[a[1]] = true;
        const imgM = block.match(/data-src="([^"]+)"/) || block.match(/src="([^"]+)"/);
        let title = '';
        const t = block.match(/hg-rank-item__title[^>]*>([\s\S]*?)<\/h2>/);
        if (t) title = stripTags(t[1]);
        if (!title) {
          const tt = block.match(/<a[^>]+href="[^"]*\/detail\/\d+\/"[^>]*>([\s\S]*?)<\/a>/);
          if (tt) title = stripTags(tt[1]);
        }
        if (!title) continue;
        const tags = block.match(/hg-rank-item__tags[^>]*>([\s\S]*?)<\/div>/);
        list.push({
          vod_id: a[1],
          vod_name: title,
          vod_pic: imgM ? fix(imgM[1]) : '',
          vod_remarks: tags ? stripTags(tags[1]) : '',
          ext: { id: a[1] },
        });
      } catch (e) {}
    }
    await withConcurrency(list.map((item) => async () => {
      if (!item.vod_pic) return;
      try {
        const raw = await fetchBinary(item.vod_pic, SITE + '/');
        const dataUri = decryptImageToDataURI(raw);
        item.vod_pic = dataUri || imgSrc(item.vod_pic);
      } catch (e) {
        item.vod_pic = imgSrc(item.vod_pic);
      }
    }), CONCURRENCY);
    return list;
  }

  // ── 接口（保持原函数名） ──────────────────────────────
  async function getLocalInfo() {
    return jsonify({ ver: 1, name: '黄果短剧', api: 'csp_huangguo', type: 3 });
  }

  async function getConfig() {
    return jsonify({
      ver: 1,
      title: '黄果短剧',
      site: SITE,
      tabs: TABS.map((t) => ({ name: t.name, ext: { id: t.id } })),
    });
  }

  async function getCards(ext) {
    ext = argsify(ext);
    const id = String(ext.id || 'home').replace(/^\//, '');
    const page = Math.max(1, parseInt(ext.page) || 1);
    try {
      if (id === 'home') {
        const html = await fetchHtml(SITE + '/');
        return jsonify({ list: await parseGridCards(html, true), page: page });
      }
      const url = SITE + '/' + id + '/' + (page > 1 ? page + '/' : '');
      const html = await fetchHtml(url);
      if (id.indexOf('rank') !== -1) {
        return jsonify({ list: await parseRanks(html), page: page });
      }
      return jsonify({ list: await parseGridCards(html, false), page: page });
    } catch (e) {
      console.error('getCards error:', e);
      return jsonify({ list: [], page: page });
    }
  }

  async function getTracks(ext) {
    ext = argsify(ext);
    const id = ext.id || '';
    if (!id) return jsonify({ list: [] });
    try {
      const html = await fetchHtml(SITE + '/detail/' + id + '/');
      const tracks = [];
      const gridM = html.match(/<div\s+class="[^"]*\bhg-web-detail__ep-grid\b[^"]*"[^>]*>([\s\S]*?)<\/div>/);
      if (gridM) {
        const are = /<a\b[^>]*>[\s\S]*?<\/a>/g;
        let m;
        while ((m = are.exec(gridM[1])) !== null) {
          const tag = m[0];
          const hrefM = tag.match(/href="([^"]+)"/);
          if (!hrefM) continue;
          const href = hrefM[1];
          const eidM = tag.match(/data-ep-id="([^"]*)"/);
          const eid = eidM ? eidM[1] : '';
          const name = eid ? '第' + eid + '集' : stripTags(tag);
          tracks.push({ name: name, ext: { url: fix(href), ep: eid } });
        }
      }
      if (!tracks.length) {
        const playM = html.match(/<a\b[^>]*class="[^"]*\bhg-web-detail__play\b[^"]*"[^>]*href="([^"]+)"/);
        if (playM) {
          tracks.push({ name: '第1集', ext: { url: fix(playM[1]), ep: '' } });
        }
      }
      if (!tracks.length) return jsonify({ list: [] });
      return jsonify({ list: [{ title: '黄果短剧', tracks: tracks }] });
    } catch (e) {
      console.error('getTracks error:', e);
      return jsonify({ list: [] });
    }
  }

  async function getPlayinfo(ext) {
    ext = argsify(ext);
    const url = ext.url || '';
    const ep = String(ext.ep || '1');
    if (!url) return jsonify({ urls: [] });
    try {
      const html = await fetchHtml(url, SITE);
      let play = '';
      const m = html.match(/id="videoInitialData"[^>]*>([\s\S]*?)<\/script>/);
      if (m) {
        try {
          const data = JSON.parse(m[1]);
          const srcs = (data && data.epPlaySrcs) || {};
          play = srcs[ep] || (data && data.videoSrc) || '';
        } catch (e) {}
      }
      if (play) {
        play = play.replace(/\\u0026/g, '&');
        if (play.indexOf('http') !== 0) {
          const mm = play.match(/(https?:\/\/[^\s"']+)/);
          play = mm ? mm[1] : '';
        }
      }
      if (!play) return jsonify({ urls: [] });
      return jsonify({
        urls: [play],
        headers: [{ 'User-Agent': UA, Referer: SITE + '/' }],
      });
    } catch (e) {
      console.error('getPlayinfo error:', e);
      return jsonify({ urls: [] });
    }
  }

  async function search(ext) {
    ext = argsify(ext);
    const kw = String(ext.text || ext.wd || '').trim();
    if (!kw) return jsonify({ list: [], page: 1 });
    try {
      const html = await fetchHtml(SITE + '/search/video/' + encodeURIComponent(kw) + '/');
      return jsonify({ list: await parseGridCards(html, false), page: 1 });
    } catch (e) {
      console.error('search error:', e);
      return jsonify({ list: [], page: 1 });
    }
  }

  // ── 图片解密 + 写回 DOM（页面实际生效的部分） ────────
  async function processImage(img) {
    const realSrc = img.getAttribute('data-src');
    if (!realSrc || img.dataset.hgDecrypted === '1') return;
    img.dataset.hgDecrypted = '1';
    try {
      const raw = await fetchBinary(realSrc, SITE + '/');
      const dataUri = decryptImageToDataURI(raw);
      if (dataUri) {
        img.src = dataUri;
        img.removeAttribute('data-src');
      } else {
        img.src = imgSrc(realSrc);
        img.removeAttribute('data-src');
      }
    } catch (e) {
      img.src = imgSrc(realSrc);
      img.removeAttribute('data-src');
    }
  }

  async function decryptAll(root) {
    root = root || document;
    const imgs = Array.from(root.querySelectorAll('img[data-src]'))
      .filter(img => /tuafjz\.cn|auth_key=/.test(img.getAttribute('data-src') || ''));
    if (!imgs.length) return;
    log('发现 ' + imgs.length + ' 张加密图，开始解密...');
    await withConcurrency(imgs.map(img => () => processImage(img)), CONCURRENCY);
    log('全部处理完成');
  }

  // ── 暴露到全局 ────────────────────────────────────────
  window.hg = {
    // 接口
    getLocalInfo, getConfig, getCards, getTracks, getPlayinfo, search,
    // 解析
    gridSlices, cardBlocks, parseCardBlock, parseGridCards, parseRanks,
    // 工具
    fix, imgSrc, stripTags, fetchHtml, fetchBinary,
    // 解密
    decryptImageToDataURI, processImage, decryptAll,
  };

  // ── 自动执行：页面已有 data-src 图就处理 ─────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => decryptAll());
  } else {
    decryptAll();
  }

  // ── 监听动态插入的卡片（无限滚动 / 分页） ────────────
  const mo = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.tagName === 'IMG' && node.hasAttribute('data-src')) {
          processImage(node);
        } else if (node.querySelectorAll) {
          node.querySelectorAll('img[data-src]').forEach(processImage);
        }
      }
    }
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });

  log('黄果短剧纯前端版已启动，可调用 window.hg.*');

})();
