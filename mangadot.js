const mangayomiSources = [
  {
    "name": "MangaDot",
    "lang": "en",
    "baseUrl": "https://mangadot.net",
    "apiUrl": "",
    "iconUrl":
      "https://www.google.com/s2/favicons?sz=128&domain=https://mangadot.net/",
    "typeSource": "single",
    "isManga": true,
    "isNsfw": false,
    "version": "0.1.3",
    "dateFormat": "",
    "dateFormatLocale": "",
    "pkgPath": "manga/src/en/mangadot.js"
  }
];

// ---------------------------------------------------------------------------
// Minimal SHA-256 / HMAC-SHA256 (the site signs chapter-image requests and the
// Mangayomi JS runtime has no WebCrypto).
// ---------------------------------------------------------------------------
function utf8Bytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const c2 = str.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000)
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 63),
        0x80 | ((c >> 6) & 63),
        0x80 | (c & 63)
      );
  }
  return out;
}

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256Bytes(bytes) {
  const msg = bytes.slice();
  const bitLen = bytes.length * 8;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  msg.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255);
  msg.push((lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);

  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];
  const w = new Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      w[i] =
        ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) |
        0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + hh) | 0;
  }
  const out = [];
  for (const v of h)
    out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  return out;
}

function hmacSha256Hex(key, message) {
  let k = utf8Bytes(key);
  if (k.length > 64) k = sha256Bytes(k);
  while (k.length < 64) k.push(0);
  const ipad = k.map((b) => b ^ 0x36);
  const opad = k.map((b) => b ^ 0x5c);
  const inner = sha256Bytes(ipad.concat(utf8Bytes(message)));
  const digest = sha256Bytes(opad.concat(inner));
  return digest.map((b) => (b < 16 ? "0" : "") + b.toString(16)).join("");
}

function randomUuid() {
  const hex = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) s += "-";
    else if (i === 14) s += "4";
    else if (i === 19) s += hex[(Math.random() * 4) | 8];
    else s += hex[(Math.random() * 16) | 0];
  }
  return s;
}

// ---------------------------------------------------------------------------

class DefaultExtension extends MProvider {
  getHeaders(url) {
    return {
      "Referer": this.source.baseUrl + "/",
    };
  }

  // Throws a readable error instead of letting the app show a silent "No result".
  checkResponse(res, what) {
    const body = res.body || "";
    const code = res.statusCode;
    const looksLikeChallenge =
      body.includes("Just a moment...") ||
      body.includes("challenge-platform") ||
      body.includes("cf-browser-verification");
    if (code === 403 || code === 503 || looksLikeChallenge) {
      throw new Error(
        `MangaDot: Cloudflare is still blocking the app (HTTP ${code}) while loading ${what}. ` +
          `Open the source in WebView, pass the check, then pull down to refresh.`
      );
    }
    if (code >= 400) {
      throw new Error(`MangaDot: HTTP ${code} while loading ${what}.`);
    }
  }

  absUrl(path) {
    if (!path) return "";
    if (path.startsWith("http")) return path;
    if (path.startsWith("//")) return "https:" + path;
    return this.source.baseUrl + (path.startsWith("/") ? "" : "/") + path;
  }

  async request(path, extraHeaders) {
    const headers = Object.assign({}, this.getHeaders(), extraHeaders || {});
    return await new Client().get(this.absUrl(path), headers);
  }

  // ---------- Browse / search ----------

  decodeEntities(s) {
    return String(s)
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&#0?39;|&apos;/g, "'")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&nbsp;/g, " ");
  }

  // The title box holds the main title followed by alternative names
  // (romaji, Japanese...). Take only the main one.
  mainTitle(el) {
    const inner = el.innerHtml || "";
    const lead = this.decodeEntities(inner.split("<")[0]).trim();
    if (lead) return lead;
    const kids = el.children || [];
    if (kids.length) {
      const first = kids[0].text.trim();
      if (first) return first;
    }
    return el.text.trim();
  }

  parseMangaList(html, page) {
    const doc = new Document(html);
    const list = [];
    const seen = {};
    for (const a of doc.select('a[href^="/manga/"]')) {
      const link = a.attr("href");
      if (!/^\/manga\/\d+$/.test(link) || seen[link]) continue;

      const divs = a.select("div");
      let name = divs.length ? this.mainTitle(divs[divs.length - 1]) : "";
      const img = a.selectFirst("img");
      if (!name && img) name = (img.attr("alt") || "").trim();
      if (!name) continue;

      seen[link] = true;
      list.push({
        name,
        imageUrl: img ? this.absUrl(img.attr("src")) : "",
        link,
      });
    }
    const hasNextPage =
      list.length > 0 &&
      (html.includes(`page=${page + 1}`) || list.length >= 28);
    return { list, hasNextPage };
  }

  async searchPage(params, page) {
    params.page = String(page);
    const qs = Object.keys(params)
      .filter((k) => params[k] !== "" && params[k] != null)
      .map((k) => `${k}=${encodeURIComponent(params[k])}`)
      .join("&");
    const res = await this.request(`/search?${qs}`);
    this.checkResponse(res, "the search page");
    return this.parseMangaList(res.body, page);
  }

  pageTitle(html) {
    const m = String(html || "").match(/<title[^>]*>([^<]*)<\/title>/i);
    return m ? m[1].trim() : "(no title)";
  }

  // Popular/Latest should never be empty on page 1. If the search page gives
  // nothing, fall back to the homepage, and if that is empty too, say why.
  async browse(params, page) {
    const result = await this.searchPage(params, page);
    if (result.list.length > 0 || page > 1) return result;

    const home = await this.request("/");
    this.checkResponse(home, "the homepage");
    const fallback = this.parseMangaList(home.body, 1);
    if (fallback.list.length > 0) {
      fallback.hasNextPage = false;
      return fallback;
    }
    throw new Error(
      `MangaDot: page loaded (HTTP ${home.statusCode}, title "${this.pageTitle(home.body)}", ` +
        `${(home.body || "").length} chars) but no manga were found on it.`
    );
  }

  async getPopular(page) {
    return await this.browse({ sortBy: "views", sortOrder: "desc" }, page);
  }

  get supportsLatest() {
    return true;
  }

  async getLatestUpdates(page) {
    return await this.browse({ sortBy: "latest", sortOrder: "desc" }, page);
  }

  async search(query, page, filters) {
    const params = {};
    if (query) params.search = query;

    let sortBy = query ? "relevance" : "latest";
    let sortOrder = "desc";
    let status = "";
    for (const f of filters || []) {
      if (f.type_name === "SortFilter" && f.state) {
        sortBy = f.values[f.state.index].value;
        sortOrder = f.state.ascending ? "asc" : "desc";
      } else if (f.name === "Status") {
        status = f.values[f.state].value;
      }
    }
    params.sortBy = sortBy;
    params.sortOrder = sortOrder;
    if (status) params.status = status;
    return await this.searchPage(params, page);
  }

  // ---------- Manga details + chapter list ----------

  mangaId(url) {
    const m = String(url).match(/manga\/(\d+)/);
    return m ? m[1] : String(url).replace(/\D/g, "");
  }

  statusCode(text) {
    return (
      {
        ongoing: 0,
        completed: 1,
        hiatus: 2,
        cancelled: 3,
        canceled: 3,
        dropped: 3,
      }[String(text || "").toLowerCase()] ?? 5
    );
  }

  parseDate(str) {
    if (!str) return null;
    // "2026-06-02 15:58:25.747371+00" -> "2026-06-02T15:58:25.747Z"
    let s = String(str)
      .trim()
      .replace(" ", "T")
      .replace(/(\.\d{3})\d+/, "$1")
      .replace(/\+00(:?00)?$/, "Z");
    const t = Date.parse(s);
    return isNaN(t) ? null : String(t);
  }

  formatNumber(n) {
    const num = parseFloat(n);
    if (isNaN(num)) return String(n);
    return num % 1 === 0 ? String(Math.floor(num)) : String(num);
  }

  async getDetail(url) {
    const id = this.mangaId(url);
    const link = `${this.source.baseUrl}/manga/${id}`;
    const res = await this.request(`/manga/${id}`);
    this.checkResponse(res, "the manga page");
    const html = res.body;
    const doc = new Document(html);

    const h1 = doc.selectFirst("h1");
    const ogTitle = doc.selectFirst("meta[property='og:title']");
    const name = h1 ? h1.text.trim() : ogTitle ? ogTitle.attr("content") : "";

    const descEl =
      doc.selectFirst("meta[name='description']") ||
      doc.selectFirst("meta[property='og:description']");
    const description = descEl ? descEl.attr("content") : "";

    let imageUrl = "";
    for (const img of doc.select("img")) {
      const src = img.attr("src") || "";
      if (src.includes("/uploads/") && !src.includes("/emojis/")) {
        imageUrl = this.absUrl(src);
        break;
      }
    }

    const genre = [];
    for (const a of doc.select('a[href^="/search?search="]')) {
      const g = a.text.trim();
      if (g && !genre.includes(g)) genre.push(g);
    }
    const author = doc
      .select('a[href^="/search?author="]')
      .map((a) => a.text.trim())
      .join(", ");
    const artist = doc
      .select('a[href^="/search?artist="]')
      .map((a) => a.text.trim())
      .join(", ");

    const statusMatch = html.match(
      />\s*(Ongoing|Completed|Hiatus|Cancelled|Canceled|Dropped)\s*</i
    );
    const status = this.statusCode(statusMatch ? statusMatch[1] : "");

    const chapters = await this.getChapters(id);

    return {
      name,
      link,
      imageUrl,
      description,
      author,
      artist,
      genre,
      status,
      chapters,
    };
  }

  // MangaDot lists every translation of a chapter. Find the English language
  // code the site uses so only English chapters are shown.
  async englishCode(mangaId) {
    try {
      const res = await this.request(
        `/api/manga/${mangaId}/chapters/filter-options`,
        { "Accept": "application/json" }
      );
      const langs = (JSON.parse(res.body).languages || []).map(String);
      return (
        langs.find((l) => l.toLowerCase() === "en") ||
        langs.find((l) => this.isEnglish(l)) ||
        null
      );
    } catch (e) {
      return null;
    }
  }

  getPref(key, fallback) {
    try {
      const v = new SharedPreferences().get(key);
      if (v === undefined || v === null || v === "") return fallback;
      if (typeof fallback === "boolean") return v === true || String(v) === "true";
      return v;
    } catch (e) {
      return fallback;
    }
  }

  preferredGroups() {
    return String(this.getPref("pref_preferred_groups", ""))
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  }

  groupNames(c) {
    if (Array.isArray(c.groups) && c.groups.length) return c.groups.map((g) => String(g.name || ""));
    return [c.group_name || c.scanlator_name || ""];
  }

  // MangaDot collects the same chapter from many groups and sites. Keep one
  // entry per chapter number, like the site's own reader does: the first
  // preferred group that has it, otherwise the earliest upload.
  onePerChapter(items, preferred) {
    const byNum = new Map();
    for (const c of items) {
      const key = Math.round((parseFloat(c.chapter_number) || 0) * 1000);
      if (!byNum.has(key)) byNum.set(key, []);
      byNum.get(key).push(c);
    }
    const rank = (c) => {
      const names = this.groupNames(c).map((n) => n.toLowerCase());
      for (let i = 0; i < preferred.length; i++) {
        if (names.some((n) => n.includes(preferred[i]))) return i;
      }
      return preferred.length;
    };
    const time = (c) => Number(this.parseDate(c.date_added)) || Number.MAX_SAFE_INTEGER;
    const out = [];
    for (const list of byNum.values()) {
      list.sort((a, b) => rank(a) - rank(b) || time(a) - time(b) || Number(a.id) - Number(b.id));
      out.push(list[0]);
    }
    return out;
  }

  isEnglish(code) {
    return /^(en([-_].*)?|eng|english)$/i.test(String(code || "").trim());
  }

  chapterLang(c) {
    return String(c.language || c.lang || c.translated_language || "");
  }

  async getChapters(mangaId) {
    const en = await this.englishCode(mangaId);
    const qs = en ? `?lang=${encodeURIComponent(en)}` : "";
    const res = await this.request(`/api/manga/${mangaId}/chapters/list${qs}`, {
      "Accept": "application/json",
    });
    this.checkResponse(res, "the chapter list");
    let data;
    try {
      data = JSON.parse(res.body);
    } catch (e) {
      throw new Error(
        "MangaDot: could not read chapter list (Cloudflare check? Open the source in WebView once)."
      );
    }
    let items = Array.isArray(data) ? data : data.chapters || data.data || [];
    // In case the server ignores ?lang=, filter here too when chapters carry a language.
    if (items.some((c) => this.chapterLang(c))) {
      const only = items.filter((c) => this.isEnglish(this.chapterLang(c)));
      if (only.length) items = only;
    }

    if (this.getPref("pref_one_per_chapter", true)) {
      items = this.onePerChapter(items, this.preferredGroups());
    }

    const chapters = items.map((c) => {
      const num = this.formatNumber(c.chapter_number);
      let name = `Chapter ${num}`;
      const title = (c.chapter_title || "").trim();
      if (title && title.toLowerCase() !== name.toLowerCase())
        name += ` - ${title}`;

      let scanlator = "";
      if (Array.isArray(c.groups) && c.groups.length)
        scanlator = c.groups.map((g) => g.name).join(", ");
      else if (c.group_name) scanlator = c.group_name;
      else if (c.scanlator_name) scanlator = c.scanlator_name;

      const url =
        c.source === "user" ? `/chapter/${c.id}?source=user` : `/chapter/${c.id}`;

      return {
        name,
        url,
        scanlator,
        dateUpload: this.parseDate(c.date_added),
        _num: parseFloat(c.chapter_number) || 0,
      };
    });

    // Newest first, as Mangayomi expects.
    chapters.sort((a, b) => b._num - a._num);
    return chapters.map(({ _num, ...rest }) => rest);
  }

  // ---------- Reader ----------

  async getPageList(url) {
    const m = String(url).match(/chapter\/(\d+)/);
    const id = m ? m[1] : String(url).replace(/\D/g, "");
    const isUpload = String(url).includes("source=user");
    const type = isUpload ? "upload" : "chapter";
    const path = isUpload
      ? `/api/uploads/${id}/images`
      : `/api/chapters/${id}/images`;

    // The site's reader fetches a short-lived token + signing key, then signs
    // the images request with HMAC-SHA256("nonce|timestamp|path").
    let token = { page_token: "", signing_key: "" };
    try {
      const tRes = await this.request(
        `/api/token/generate?chapter_id=${id}&type=${type}`,
        { "Accept": "application/json" }
      );
      token = JSON.parse(tRes.body) || token;
    } catch (e) {
      // fall through and try unsigned
    }

    const headers = { "Accept": "application/json" };
    if (token.page_token || token.signing_key) {
      const nonce = randomUuid();
      const ts = String(Math.floor(Date.now() / 1000));
      headers["X-Page-Token"] = token.page_token;
      headers["X-Nonce"] = nonce;
      headers["X-Timestamp"] = ts;
      headers["X-Signature"] = hmacSha256Hex(
        token.signing_key,
        `${nonce}|${ts}|${path}`
      );
    }

    const res = await this.request(path, headers);
    this.checkResponse(res, "the chapter pages");
    let data;
    try {
      data = JSON.parse(res.body);
    } catch (e) {
      throw new Error(`MangaDot: failed to load pages (${res.statusCode}).`);
    }

    const imgHeaders = this.getHeaders();
    return (data.images || []).map((img) => ({
      url: this.absUrl(typeof img === "string" ? img : img.url),
      headers: imgHeaders,
    }));
  }

  // ---------- Filters / prefs ----------

  getFilterList() {
    return [
      {
        type_name: "SortFilter",
        type: "sort",
        name: "Sort",
        state: { type_name: "SortState", index: 0, ascending: false },
        values: [
          ["Latest", "latest"],
          ["Most viewed", "views"],
          ["Most tracked", "tracked"],
          ["Top rated", "rating"],
          ["Chapters", "chapters"],
          ["A → Z", "alphabetical"],
          ["Relevance (with search text)", "relevance"],
        ].map((x) => ({ type_name: "SelectOption", name: x[0], value: x[1] })),
      },
      {
        type_name: "SelectFilter",
        name: "Status",
        state: 0,
        values: [
          ["Any", ""],
          ["Ongoing", "ongoing"],
          ["Completed", "completed"],
          ["Hiatus", "hiatus"],
        ].map((x) => ({ type_name: "SelectOption", name: x[0], value: x[1] })),
      },
    ];
  }

  getSourcePreferences() {
    return [
      {
        key: "pref_one_per_chapter",
        switchPreferenceCompat: {
          title: "One entry per chapter",
          summary:
            "MangaDot has the same chapter from many groups. On: show one copy per chapter. Off: show every copy.",
          value: true,
        },
      },
      {
        key: "pref_preferred_groups",
        editTextPreference: {
          title: "Preferred groups",
          summary:
            "Comma-separated, in order of preference, e.g. VIZ Media, TCB Scans. Empty: earliest upload, like the website.",
          value: "",
          dialogTitle: "Preferred groups",
          dialogMessage: "Comma-separated group names, best first",
          text: "",
        },
      },
    ];
  }

  async getVideoList(url) {
    throw new Error("getVideoList not implemented");
  }
}
