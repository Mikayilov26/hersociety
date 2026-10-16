/* HER Society · Çay Süfrəsi — shared helpers */
const HS = {
  SALT: 'hersociety-cay-sufresi-2026',
  ITER: 150000,
  CHECK: 'SFQYGfFZ4kLv',
  MAP: 'https://maps.app.goo.gl/szwMXMpqajJ72bJh8',
  IG: 'https://instagram.com/hersociety.az',
  ALPHA: 'ABCDEFGHJKMNPQRSTUVWXYZ23456789',
  KEY_STORE: 'hs_key_v1',

  base() { return location.origin + location.pathname.replace(/[^/]*$/, ''); },

  b64u(bytes) { let s = ''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  unb64u(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; const s = atob(str); return Uint8Array.from(s, c => c.charCodeAt(0)); },
  encName(name) { return HS.b64u(new TextEncoder().encode(name)); },
  decName(b) { return new TextDecoder('utf-8', { fatal: true }).decode(HS.unb64u(b)); },

  async deriveRaw(pin) {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(HS.SALT), iterations: HS.ITER, hash: 'SHA-256' }, base, 256);
    return new Uint8Array(bits);
  },
  async hmacKey(raw) { return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); },
  async mac(key, str) { const s = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(str)); return HS.b64u(new Uint8Array(s)); },

  /* PIN -> key, or null if wrong */
  async login(pin) {
    const raw = await HS.deriveRaw(pin.trim().toLowerCase());
    const key = await HS.hmacKey(raw);
    if ((await HS.mac(key, 'hersociety-check')).slice(0, 12) !== HS.CHECK) return null;
    try { localStorage.setItem(HS.KEY_STORE, HS.b64u(raw)); } catch (e) {}
    return key;
  },
  async storedKey() {
    try { const r = localStorage.getItem(HS.KEY_STORE); if (!r) return null; const key = await HS.hmacKey(HS.unb64u(r)); if ((await HS.mac(key, 'hersociety-check')).slice(0, 12) !== HS.CHECK) return null; return key; } catch (e) { return null; }
  },
  logout() { try { localStorage.removeItem(HS.KEY_STORE); } catch (e) {} },

  /* 6-char code: 4 random + 2 check chars signed with the key, so a typed code can be verified */
  async idCheck(key, r4) { const m = HS.unb64u(await HS.mac(key, 'id:' + r4)); return HS.ALPHA[m[0] % HS.ALPHA.length] + HS.ALPHA[m[1] % HS.ALPHA.length]; },
  async newId(key) { const a = new Uint8Array(4); crypto.getRandomValues(a); const r4 = Array.from(a, x => HS.ALPHA[x % HS.ALPHA.length]).join(''); return r4 + await HS.idCheck(key, r4); },
  async validId(key, id) { return /^[A-Z0-9]{6}$/.test(id) && (await HS.idCheck(key, id.slice(0, 4))) === id.slice(4); },

  /* token = ID.NUM.NAME.SIG */
  async makeToken(key, id, num, name) {
    const payload = `${id}.${num}.${HS.encName(name)}`;
    const sig = (await HS.mac(key, payload)).slice(0, 16);
    return `${payload}.${sig}`;
  },
  guestUrl(token) { return HS.base() + '#t=' + token; },

  /* parse without verifying (guest page) */
  parse(text) {
    if (!text) return null;
    let t = String(text).trim();
    const i = t.indexOf('#t='); if (i >= 0) t = t.slice(i + 3);
    t = decodeURIComponent(t);
    const p = t.split('.');
    if (p.length !== 4) return null;
    const [id, num, nb, sig] = p;
    if (!/^[A-Z0-9]{6}$/.test(id) || !/^\d{1,4}$/.test(num) || !/^[A-Za-z0-9_-]{16}$/.test(sig)) return null;
    let name; try { name = HS.decName(nb); } catch (e) { return null; }
    return { id, num: +num, name, sig, payload: `${id}.${num}.${nb}` };
  },
  async verify(key, text) {
    const t = HS.parse(text); if (!t) return null;
    const exp = (await HS.mac(key, t.payload)).slice(0, 16);
    return exp === t.sig && await HS.validId(key, t.id) ? t : null;
  },
  /* guest list for the door phone: [[id,num,name],...] packed + signed */
  async packList(key, rows) { const body = HS.b64u(new TextEncoder().encode(JSON.stringify(rows))); return body + '.' + (await HS.mac(key, 'list:' + body)).slice(0, 16); },
  async unpackList(key, str) {
    const i = str.lastIndexOf('.'); if (i < 0) return null;
    const body = str.slice(0, i), sig = str.slice(i + 1);
    if ((await HS.mac(key, 'list:' + body)).slice(0, 16) !== sig) return null;
    try { const d = JSON.parse(new TextDecoder().decode(HS.unb64u(body))); return (d && typeof d === 'object') ? d : null; } catch (e) { return null; }
  },
  pad(n) { return String(n).padStart(2, '0'); },
  esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); },
  load(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
  save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } },
};
