/* guldo_verify.js: check a Guldo agent-evaluation bundle in the browser (or Node), with no server, no packages and no network except fetching the bundle's own files.

   It is a PORT of the parts of `agent_verifier.py audit` that need only hashes and signatures: the manifest, the round's hash-chained log, the seed reveal against its commitment, the joint seed,
   the registry (chain, signatures, key history, "registered before it ran", outcome), and every certificate's signature and its bindings to the round. Each check has one of four states:

     pass  the check ran and the bundle satisfied it
     fail  the check ran and the bundle did NOT satisfy it
     info  a fact worth knowing, not a test
     skip  the check could not run HERE (and the list says what to run instead)

   What it does NOT do (always listed in the result): re-derive every instance from the seed and replay every tool call (needs the Python task code), regenerate each certificate's statistics, verify the
   per-session service signatures, the drand beacon, the evidence log's inclusion proofs and witness timelines, and hardware attestation. The Python audit does those. A browser "pass" is therefore
   narrower than "AUDIT PASSED", and the page says so.

   Trust: a signature only shows that the holder of a KEY signed. Whether that key belongs to a verifier you can trust is a fact about people; you supply it (`pinned`). Nothing here fetches a key for you.
   Everything read from a bundle is untrusted data: this module never evaluates it, and the page that renders it escapes it.

   Canonical JSON must match Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` byte for byte, because every hash is over that text. JSON.parse cannot do it (it loses
   the difference between 2.0 and 2), so this file has its own parser that keeps each number's original text. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.GuldoVerify = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const ZERO = "0".repeat(64);
  const HEX64 = /^[0-9a-f]{64}$/;
  const SHARE_RE = /^[0-9a-f]{64}$/;
  const PARTY_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{1,39}$/;
  const CEREMONY_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
  const ROUND_KINDS = ["round_open", "round_close", "round_void"];
  const KEY_KINDS = ["key_inception", "key_rotation", "key_retire"];
  const BUNDLE_FORMAT = "guldo-agent-bundle-v1";
  const CERT_FORMAT = "guldo-agent-certificate-v1";
  const JOINT_FORMAT = "guldo-joint-seed-v1";
  const COMMIT_FORMAT = "guldo-joint-commit-v1";
  const MAX_FILES = 2000, MAX_BYTES = 100 << 20;       // a browser tab reads the whole bundle into memory: refuse what could freeze it

  // ---------------------------------------------------------------- bytes, hashes

  const te = new TextEncoder();

  function webcrypto() {
    const c = typeof globalThis !== "undefined" ? globalThis.crypto : undefined;
    if (!c || !c.subtle) throw new Error("this browser context has no WebCrypto (open the page over https)");
    return c;
  }

  function toBytes(x) { return typeof x === "string" ? te.encode(x) : x; }

  function bytesToHex(b) {
    let s = "";
    for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }

  function hexToBytes(h) {
    if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) return null;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  async function digest(alg, data) {
    return new Uint8Array(await webcrypto().subtle.digest(alg, toBytes(data)));
  }

  async function sha256hex(data) { return bytesToHex(await digest("SHA-256", data)); }

  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // ---------------------------------------------------------------- JSON that keeps number text, and Python-identical canonical form

  class Num {
    constructor(raw) { this.raw = raw; }
    valueOf() { return Number(this.raw); }
  }

  const NUM_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

  function parseJSON(text) {
    let i = 0;
    const n = text.length;
    function fail(msg) { throw new Error("JSON: " + msg + " at " + i); }
    function ws() { while (i < n && (text[i] === " " || text[i] === "\n" || text[i] === "\r" || text[i] === "\t")) i++; }
    function value(depth) {
      if (depth > 200) fail("nested too deeply");
      ws();
      if (i >= n) fail("unexpected end");
      const c = text[i];
      if (c === "{") {
        i++;
        const o = Object.create(null);
        ws();
        if (text[i] === "}") { i++; return o; }
        for (;;) {
          ws();
          if (text[i] !== '"') fail("expected a key");
          const k = str();
          if (k in o) fail("duplicate key " + JSON.stringify(k));
          ws();
          if (text[i] !== ":") fail("expected ':'");
          i++;
          o[k] = value(depth + 1);
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "}") { i++; return o; }
          fail("expected ',' or '}'");
        }
      }
      if (c === "[") {
        i++;
        const a = [];
        ws();
        if (text[i] === "]") { i++; return a; }
        for (;;) {
          a.push(value(depth + 1));
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "]") { i++; return a; }
          fail("expected ',' or ']'");
        }
      }
      if (c === '"') return str();
      if (text.startsWith("true", i)) { i += 4; return true; }
      if (text.startsWith("false", i)) { i += 5; return false; }
      if (text.startsWith("null", i)) { i += 4; return null; }
      const m = /^-?[0-9][0-9.eE+-]*/.exec(text.slice(i, i + 64));
      if (!m || !NUM_RE.test(m[0])) fail("bad value");
      i += m[0].length;
      return new Num(m[0]);
    }
    function str() {
      i++;
      let out = "";
      for (;;) {
        if (i >= n) fail("unterminated string");
        const c = text[i];
        if (c === '"') { i++; return out; }
        if (c === "\\") {
          const e = text[i + 1];
          i += 2;
          if (e === "n") out += "\n"; else if (e === "t") out += "\t"; else if (e === "r") out += "\r";
          else if (e === "b") out += "\b"; else if (e === "f") out += "\f"; else if (e === "/") out += "/";
          else if (e === '"') out += '"'; else if (e === "\\") out += "\\";
          else if (e === "u") {
            const h = text.substr(i, 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u escape");
            out += String.fromCharCode(parseInt(h, 16));
            i += 4;
          } else fail("bad escape");
        } else {
          if (c.charCodeAt(0) < 0x20) fail("control character in string");
          out += c;
          i++;
        }
      }
    }
    const v = value(0);
    ws();
    if (i < n) fail("trailing text");
    return v;
  }

  function cmpCodePoints(a, b) {
    const x = Array.from(a), y = Array.from(b);
    const m = Math.min(x.length, y.length);
    for (let i = 0; i < m; i++) {
      const d = x[i].codePointAt(0) - y[i].codePointAt(0);
      if (d) return d;
    }
    return x.length - y.length;
  }

  function jsonString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      const ch = s[i];
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");   // Python's ensure_ascii escapes everything outside space..~ (DEL included), in lower-case hex, astral characters as two surrogates
      else out += ch;
    }
    return out + '"';
  }

  function canon(v) {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (v instanceof Num) return v.raw;
    if (typeof v === "string") return jsonString(v);
    if (typeof v === "number") throw new Error("canon: a bare JS number has no Python-identical text; parse with parseJSON so numbers keep their own text");
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    if (typeof v === "object") {
      return "{" + Object.keys(v).sort(cmpCodePoints).map((k) => jsonString(k) + ":" + canon(v[k])).join(",") + "}";
    }
    throw new Error("canon: unsupported value");
  }

  function without(o, ...keys) {
    const out = Object.create(null);
    for (const k of Object.keys(o)) if (!keys.includes(k)) out[k] = o[k];
    return out;
  }

  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Num);
  const isNumber = (v) => v instanceof Num;
  const isInt = (v) => v instanceof Num && /^-?[0-9]+$/.test(v.raw);
  const nv = (v) => (v instanceof Num ? Number(v.raw) : NaN);
  const same = (a, b) => canon(a) === canon(b);
  const get1 = (o, ...path) => { for (const k of path) { if (!isObj(o)) return undefined; o = o[k]; } return o; };

  function lines(text) {
    return text.split("\n").filter((l) => l.trim() !== "").map(parseJSON);
  }

  // ---------------------------------------------------------------- Ed25519 (RFC 8032), the same strictness as agent_sig.verify

  const P = (1n << 255n) - 19n;
  const Q = (1n << 252n) + 27742317777372353535851937790883648493n;
  const md = (a) => { const r = a % P; return r >= 0n ? r : r + P; };

  function modpow(b, e, m) {
    let r = 1n;
    b %= m;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  const inv = (x) => modpow(md(x), P - 2n, P);
  const D = md(-121665n * inv(121666n));
  const SQRT_M1 = modpow(2n, (P - 1n) / 4n, P);

  function recoverX(y, sign) {
    if (y >= P) return null;
    const x2 = md((y * y - 1n) * inv(D * y * y + 1n));
    if (x2 === 0n) return sign ? null : 0n;
    let x = modpow(x2, (P + 3n) / 8n, P);
    if (md(x * x - x2) !== 0n) x = md(x * SQRT_M1);
    if (md(x * x - x2) !== 0n) return null;
    if ((x & 1n) !== BigInt(sign)) x = P - x;
    return x;
  }

  const GY = md(4n * inv(5n));
  const GX = recoverX(GY, 0);
  const G = [GX, GY, 1n, md(GX * GY)];
  const IDENT = [0n, 1n, 1n, 0n];

  function add(a, b) {
    const A = md((a[1] - a[0]) * (b[1] - b[0]));
    const B = md((a[1] + a[0]) * (b[1] + b[0]));
    const C = md(2n * a[3] * b[3] * D);
    const Dd = md(2n * a[2] * b[2]);
    const E = B - A, F = Dd - C, G_ = Dd + C, H = B + A;
    return [md(E * F), md(G_ * H), md(F * G_), md(E * H)];
  }

  function mul(s, pt) {
    let r = IDENT;
    while (s > 0n) { if (s & 1n) r = add(r, pt); pt = add(pt, pt); s >>= 1n; }
    return r;
  }

  const eq = (a, b) => md(a[0] * b[2] - b[0] * a[2]) === 0n && md(a[1] * b[2] - b[1] * a[2]) === 0n;

  function leInt(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  }

  function decompress(s) {
    if (s.length !== 32) return null;
    let y = leInt(s);
    const sign = Number(y >> 255n);
    y &= (1n << 255n) - 1n;
    const x = recoverX(y, sign);
    return x === null ? null : [x, y, 1n, md(x * y)];
  }

  /** True only for a valid signature; never throws. pub, msg, sig are Uint8Arrays. Refuses small-order keys and nonces, and s >= the group order, like libsodium and agent_sig.verify. */
  async function ed25519Verify(pub, msg, sig) {
    try {
      if (!(pub instanceof Uint8Array) || !(msg instanceof Uint8Array) || !(sig instanceof Uint8Array)) return false;
      if (pub.length !== 32 || sig.length !== 64) return false;
      const A = decompress(pub), R = decompress(sig.subarray(0, 32));
      if (!A || !R) return false;
      if (eq(mul(8n, A), IDENT) || eq(mul(8n, R), IDENT)) return false;
      const s = leInt(sig.subarray(32));
      if (s >= Q) return false;
      const h = leInt(await digest("SHA-512", concat(sig.subarray(0, 32), pub, msg))) % Q;
      return eq(mul(s, G), add(R, mul(h, A)));
    } catch (e) {
      return false;
    }
  }

  async function sigOk(pubHex, msg, sigHex) {
    const pub = hexToBytes(pubHex), sig = hexToBytes(sigHex);
    if (!pub || !sig) return false;
    return ed25519Verify(pub, toBytes(msg), sig);
  }

  /** {statement, signature}: the signature is over the canonical JSON of the statement, which carries the signer's own public key. */
  async function statementOk(signed) {
    try {
      const st = signed.statement;
      return await sigOk(st.pubkey, canon(st), signed.signature);
    } catch (e) {
      return false;
    }
  }

  // ---------------------------------------------------------------- the round log (rounds.verify_log)

  async function logEntryHash(e) { return sha256hex(e.prev + canon(without(e, "hash"))); }

  async function checkLog(log, rid) {
    if (!log.length) return "empty log";
    let prev = await sha256hex("genesis:" + rid);
    for (let i = 0; i < log.length; i++) {
      const e = log[i];
      if (!isObj(e)) return "entry " + i + " is not an object";
      if (nv(e.seq) !== i) return "entry " + i + ": sequence number " + (e.seq && e.seq.raw) + " (an entry was dropped, duplicated or reordered)";
      if (e.prev !== prev) return "entry " + i + ": does not chain to the previous entry";
      if ((await logEntryHash(e)) !== e.hash) return "entry " + i + ": contents do not match their hash (altered)";
      if (!isNumber(e.ts)) return "entry " + i + ": has no numeric timestamp";
      if (i > 0 && nv(e.ts) < nv(log[i - 1].ts) - 1) return "entry " + i + ": timestamp earlier than the previous entry (back-dated)";
      prev = e.hash;
    }
    if (log[0].kind !== "round_created") return "the first entry is not round_created";
    return null;
  }

  // ---------------------------------------------------------------- the registry (agent_registry.walk and round_problems)

  async function registryEntryHash(e) { return sha256hex(e.prev + canon(without(e, "hash", "sig"))); }

  const validCommit = (c) => c === null || c === undefined || (typeof c === "string" && HEX64.test(c));

  async function registryWalk(rows) {
    const probs = [], terms = [];
    let prev = ZERO, last = 0, active = null, nextCommit = null, retired = false;
    const state = Object.create(null);
    for (let i = 0; i < rows.length; i++) {
      const e = rows[i];
      try {
        if (nv(e.seq) !== i) probs.push("entry " + i + " is numbered " + (e.seq && e.seq.raw));
        if (e.prev !== prev) probs.push("entry " + i + " does not follow the one before it");
        if (e.hash !== (await registryEntryHash(e))) probs.push("entry " + i + "'s hash is not its content's");
        const pk = e.pubkey;
        if (!(await sigOk(pk, e.hash, e.sig))) probs.push("entry " + i + "'s signature is not valid");
        if (!isNumber(e.ts) || nv(e.ts) < last) probs.push("entry " + i + "'s time runs backwards");
        else last = nv(e.ts);
        const kind = e.kind, data = e.data;
        if (!ROUND_KINDS.includes(kind) && !KEY_KINDS.includes(kind) || !isObj(data)) {
          probs.push("entry " + i + " is not a recognised event");
          prev = e.hash;
          continue;
        }
        if (retired) probs.push("entry " + i + " comes after the identity was retired");
        if (i === 0) {
          if (kind === "key_rotation" || kind === "key_retire") probs.push("the first entry cannot be a " + kind.slice(4) + ": there is no key to hand over from");
          active = pk;
          nextCommit = kind === "key_inception" ? (data.next === undefined ? null : data.next) : null;
          if (kind === "key_inception" && !validCommit(data.next)) { probs.push("the inception's next-key commitment is malformed"); nextCommit = null; }
          terms.push({ key: pk, from_seq: 0, to_seq: null, compromised_since: null });
        } else if (kind === "key_inception") probs.push("entry " + i + ": an inception is only valid as the first entry");
        if (kind === "key_rotation" && i > 0) {
          const np = data.new_pubkey, cs = data.compromised_since === undefined ? null : data.compromised_since;
          const hexKey = hexToBytes(np);
          if (pk !== np) probs.push("entry " + i + ": a rotation must be signed by the NEW key it names");
          else if (nextCommit === null || !hexKey || (await sha256hex(hexKey)) !== nextCommit) probs.push("entry " + i + ": the new key is not the one the previous key committed to (a rotation needs the pre-committed key, which a thief of the current key does not have)");
          else if (Object.values(state).some((v) => v === "open")) probs.push("entry " + i + ": a key rotation while a round is open");
          else if (!validCommit(data.next) || !(cs === null || (isInt(cs) && terms[terms.length - 1].from_seq <= nv(cs) && nv(cs) <= i - 1))) probs.push("entry " + i + ": the rotation's next-key commitment or compromise point is malformed");
          else {
            const t = terms[terms.length - 1];
            t.to_seq = i - 1; t.compromised_since = cs === null ? null : nv(cs);
            active = np; nextCommit = data.next === undefined ? null : data.next;
            terms.push({ key: np, from_seq: i, to_seq: null, compromised_since: null });
          }
        } else if (i > 0 && pk !== active) probs.push("entry " + i + " is signed by a key that is not the active key");
        if (kind === "key_retire") { retired = true; terms[terms.length - 1].to_seq = i; }
        if (ROUND_KINDS.includes(kind)) {
          const rid = data.round;
          if (typeof rid !== "string") probs.push("entry " + i + " names no round");
          else if (kind === "round_open") {
            if (rid in state) probs.push("entry " + i + " opens round " + rid + " a second time");
            state[rid] = "open";
          } else {
            if (state[rid] !== "open") probs.push("entry " + i + " " + kind.slice(6) + "s round " + rid + ", which is " + (rid in state ? state[rid] : "not open"));
            state[rid] = kind === "round_close" ? "closed" : "void";
          }
        }
        prev = e.hash;
      } catch (err) {
        probs.push("entry " + i + " is malformed");
        break;
      }
    }
    return { probs, terms };
  }

  function registryRounds(rows) {
    const out = Object.create(null);
    for (const e of rows) {
      if (!ROUND_KINDS.includes(e.kind)) continue;
      const rid = e.data.round;
      if (e.kind === "round_open") out[rid] = { open: e, end: null, status: "open" };
      else if (rid in out) { out[rid].end = e; out[rid].status = e.kind === "round_close" ? "closed" : "void"; }
    }
    return out;
  }

  const trustedFrom = (terms, pins) => {
    const starts = terms.filter((t) => pins.includes(t.key)).map((t) => t.from_seq);
    return starts.length ? Math.min(...starts) : null;
  };
  const termAt = (terms, seq) => terms.find((t) => t.from_seq <= seq && (t.to_seq === null || seq <= t.to_seq)) || null;

  // ---------------------------------------------------------------- the joint seed (agent_joint.verify), without the beacon

  async function jointProblems(joint, revealed, roundCommitment, partyPins) {
    const probs = [];
    let usesBeacon = false;
    try {
      if (joint.format !== JOINT_FORMAT || revealed.format !== JOINT_FORMAT + "-revealed") return { probs: ["not a joint-seed record"], usesBeacon };
      const ceremony = joint.ceremony;
      if (typeof ceremony !== "string" || !CEREMONY_RE.test(ceremony)) return { probs: ["a ceremony id is 1-64 letters, digits and _ . : -"], usesBeacon };
      if (revealed.ceremony !== ceremony) return { probs: ["the revealed shares are for another ceremony"], usesBeacon };
      const parties = Object.create(null);
      const plans = new Set();
      for (const c of joint.parties) {
        const st = c && c.statement;
        if (!isObj(st) || st.format !== COMMIT_FORMAT) { probs.push("not a joint-seed commitment"); continue; }
        if (!(await statementOk(c))) probs.push("the commitment's signature is not valid");
        if (st.ceremony !== ceremony) probs.push("the commitment is for ceremony " + JSON.stringify(st.ceremony) + ", not " + JSON.stringify(ceremony));
        if (typeof st.party !== "string" || !PARTY_RE.test(st.party)) probs.push("a party name is 2-40 letters, digits and _ . : -");
        else parties[st.party] = c;
        plans.add(st.beacon === undefined || st.beacon === null ? "none" : canon(st.beacon));
      }
      const shares = revealed.shares;
      if (!isObj(shares)) return { probs: probs.concat("the revealed record has no shares"), usesBeacon };
      if (Object.keys(parties).length < 2) probs.push("fewer than 2 parties");
      const a = Object.keys(parties).sort(), b = Object.keys(shares).sort();
      if (a.join("\n") !== b.join("\n")) { probs.push("the parties that committed are not the parties that revealed"); return { probs, usesBeacon }; }
      const keys = Object.create(null);
      for (const p of b) {
        const s = shares[p];
        if (typeof s !== "string" || !SHARE_RE.test(s)) { probs.push("share of " + p + " is not 64 hex characters"); continue; }
        if ((await sha256hex("guldo-joint-commit-v1|" + ceremony + "|" + p + "|" + s)) !== parties[p].statement.commitment) probs.push("party " + p + "'s revealed share does not match its signed commitment");
        keys[p] = parties[p].statement.pubkey;
      }
      if (new Set(Object.values(keys)).size !== Object.keys(keys).length) probs.push("two parties signed with the SAME key: that is one party, not two");
      if (partyPins) for (const p of Object.keys(keys).sort()) if (!partyPins.includes(keys[p])) probs.push("party " + p + "'s key is not one you pinned");
      if (plans.size !== 1) probs.push("the parties do not agree about the beacon round (every party must sign the same round, or none)");
      usesBeacon = !(plans.size === 1 && plans.has("none"));
      if (!probs.length && !usesBeacon) {
        if (joint.beacon_plan !== undefined && joint.beacon_plan !== null) probs.push("the joint record's beacon plan is not what the parties signed");
        const text = "guldo-joint-seed-v1|" + ceremony + "|" + b.map((p) => p + "=" + shares[p]).join("|");
        const master = await sha256hex(text);
        if ((await sha256hex(master)) !== joint.master_sha256) probs.push("the combined seed is not the one the joint record names");
        if (roundCommitment !== undefined && (await sha256hex(concat(te.encode("guldo-agent-commit|"), te.encode(master)))) !== roundCommitment)
          probs.push("the combined seed does not produce the round's seed commitment: the round was not run on this joint seed");
      }
    } catch (e) {
      probs.push("malformed joint record (" + (e && e.name) + ")");
    }
    return { probs, usesBeacon };
  }

  // ---------------------------------------------------------------- the bundle

  function safePath(p) {
    return typeof p === "string" && p.length > 0 && !p.startsWith("/") && !p.includes("\\") && !p.split("/").some((s) => s === ".." || s === "." || s === "");
  }

  const NOT_CHECKED_HERE = [
    ["instances and sessions", "Re-deriving every instance from the revealed seed, re-running every verifier, replaying every tool call and recomputing every cost needs the Python task code. Run: python3 agent_verifier.py audit BUNDLE --trusted YOUR_KEYS"],
    ["certificate statistics", "That each certificate's counts, sign test and statement text regenerate from the ladders. The Python audit regenerates them; this page only shows the text the certificate carries."],
    ["session signatures", "That every black-box session in the ladders really carries a valid signature from that service key. This page checks which key each ladder names and matches each ladder file by hash to the round log, but does not replay the sessions' chains."],
    ["ladder digests", "The ladder digest each log entry records is compared with the certificate and the registry, but is not recomputed from the ladder's records here."],
    ["public randomness and the evidence log", "A drand beacon in the joint seed, the transparency log's inclusion proofs and witness timelines, and hardware attestation are verified only by the Python audit."],
    ["who the keys belong to", "Distinct keys are not distinct people, and nothing here can show the verifier did not leak instances while the round ran."],
  ];

  /**
   * files: {path: Uint8Array} for the bundle folder (paths relative to the folder).
   * opts.pinned: hex public keys YOU trust for the verifier. opts.partyPins: optional hex keys for the joint-seed parties.
   * opts.complete: true when `files` is the whole folder (so an unlisted extra file is a failure); false when only the manifest's own files were fetched.
   * opts.keySource: "you" | "link" | "site" | "none": where the pinned key came from, carried into the verdict.
   */
  async function verifyBundle(files, opts) {
    opts = opts || {};
    const pinned = (opts.pinned || []).map((k) => String(k).trim().toLowerCase()).filter((k) => HEX64.test(k));
    const checks = [];
    const add = (id, title, status, detail) => checks.push({ id, title, status, detail: detail || "" });
    const text = (p) => new TextDecoder("utf-8", { fatal: true }).decode(files[p]);
    const guard = async (id, title, fn) => {
      try { await fn(); } catch (e) { add(id, title, "fail", "could not be checked: " + (e && e.message ? e.message : String(e))); }
    };

    const ctx = { rid: null, manifest: null };
    let log = null, roundJson = null, plan = null, entriesMap = Object.create(null), entriesList = [], jointDoc = null, regRows = null, results = {};
    let jointKeys = null;                 // {party: key} once the joint seed has verified
    const verifierKeys = new Set();       // the keys that acted as THE verifier in this round (registry identity, certificate signers, black-box service keys): for key separation

    // -- the manifest
    await guard("manifest", "every file in the bundle is the one the manifest lists", async () => {
      if (!files["BUNDLE.json"]) { add("manifest", "every file in the bundle is the one the manifest lists", "fail", "there is no BUNDLE.json"); return; }
      const m = parseJSON(text("BUNDLE.json"));
      if (!isObj(m) || m.format !== BUNDLE_FORMAT || !isObj(m.files) || typeof m.round !== "string") { add("manifest", "every file in the bundle is the one the manifest lists", "fail", "BUNDLE.json is not a " + BUNDLE_FORMAT + " manifest"); return; }
      ctx.manifest = m; ctx.rid = m.round;
      const problems = [];
      for (const p of Object.keys(m.files).sort()) {
        if (!safePath(p)) { problems.push("unsafe path " + JSON.stringify(p)); continue; }
        if (!files[p]) { problems.push("missing: " + p); continue; }
        if ((await sha256hex(files[p])) !== m.files[p]) problems.push("altered: " + p);
      }
      if (opts.complete) for (const p of Object.keys(files)) if (p !== "BUNDLE.json" && p !== "README.txt" && !(p in m.files)) problems.push("not in the manifest: " + p);   // README.txt is exempt, as in the Python audit
      const n = Object.keys(m.files).length;
      add("manifest", "every file in the bundle is the one the manifest lists" + (opts.complete ? ", and there are no others" : ""),
        problems.length ? "fail" : "pass", problems.length ? problems.slice(0, 4).join("; ") : n + " files" + (opts.complete ? "" : " (a bundle fetched by link: extra unlisted files cannot be detected; load the folder to check for them)"));
    });
    if (!ctx.rid) return finish(checks, pinned, opts, ctx, null);

    const rid = ctx.rid;
    const R = "round/agent-rounds/" + rid + "/";
    const need = (p) => { if (!files[p]) throw new Error("the bundle has no " + p); };

    // -- the round log, plan and commitment
    await guard("log", "the round's log is one hash chain from its first entry to its last", async () => {
      need(R + "log.jsonl"); need(R + "round.json"); need(R + "plan.json");
      log = lines(text(R + "log.jsonl"));
      roundJson = parseJSON(text(R + "round.json"));
      plan = parseJSON(text(R + "plan.json"));
      const err = await checkLog(log, rid);
      add("log", "the round's log is one hash chain from its first entry to its last", err ? "fail" : "pass", err || log.length + " entries, head " + log[log.length - 1].hash.slice(0, 16));
    });
    if (log) await guard("plan", "the plan, its hash and the seed commitment are the ones the log's first entry fixed", async () => {
      const first = log[0].data;
      const bad = [];
      const ph = await sha256hex(canon(plan));
      if (!same(plan, first.plan)) bad.push("plan.json is not the plan the log recorded");
      if (ph !== first.plan_hash || ph !== roundJson.plan_hash) bad.push("the plan's hash is not the one logged");
      if (!Array.isArray(first.commitments) || first.commitments.length !== 1 || first.commitments[0] !== roundJson.commitment || plan.commit !== roundJson.commitment) bad.push("the seed commitment differs between plan, round and log");
      add("plan", "the plan, its hash and the seed commitment are the ones the log's first entry fixed", bad.length ? "fail" : "pass", bad[0] || "plan " + ph.slice(0, 16) + ", commitment " + String(roundJson.commitment).slice(0, 16));
    });

    // -- the entry files, in file-name order (the order the registry recorded the arms in)
    if (log) await guard("entries", "the round's entry files can be read", async () => {
      const names = Object.keys(files).filter((p) => p.startsWith(R + "entries/") && p.endsWith(".json")).sort();
      for (const p of names) { const e = parseJSON(text(p)); if (!isObj(e) || typeof e.eid !== "string") throw new Error(p + " is not an entry"); entriesMap[e.eid] = e; entriesList.push(e); }
    });

    // -- the seed reveal
    if (log) await guard("reveal", "the revealed seed matches the commitment made before any arm ran", async () => {
      const revealed = log.find((e) => e.kind === "revealed");
      const p = R + "seed.revealed";
      if (!files[p] && !revealed) { add("reveal", "the revealed seed matches the commitment made before any arm ran", "skip", "this round has not revealed its seed yet, so nothing can be re-derived from it"); return; }
      if (!files[p] || !revealed) { add("reveal", "the revealed seed matches the commitment made before any arm ran", "fail", "the seed file and the log's reveal entry must both exist"); return; }
      const master = text(p).trim();
      const bad = [];
      if ((await sha256hex(concat(te.encode("guldo-agent-commit|"), te.encode(master)))) !== roundJson.commitment) bad.push("the revealed seed does not match the commitment");
      if ((await sha256hex(master)) !== revealed.data.seed_sha256) bad.push("the revealed seed is not the one logged");
      add("reveal", "the revealed seed matches the commitment made before any arm ran", bad.length ? "fail" : "pass", bad[0] || "commitment " + roundJson.commitment.slice(0, 16));
    });

    // -- arms, ladders, results
    if (log) await guard("ladders", "each ladder file is byte-identical to the one the log recorded when the arm was evaluated", async () => {
      const ev = log.filter((e) => e.kind === "evaluated");
      if (!ev.length) { add("ladders", "each ladder file is byte-identical to the one the log recorded when the arm was evaluated", "skip", "the round has not evaluated any arm"); return; }
      const bad = [];
      for (const e of ev) {
        const f = R + "ladders/" + e.data.eid + ".jsonl";
        if (!files[f]) { bad.push("missing ladder for " + e.data.eid); continue; }
        if ((await sha256hex(files[f])) !== e.data.ladder_sha256) bad.push("the " + e.data.eid + " ladder is not the one the log recorded");
      }
      const planned = ["baseline"].concat(entriesList.map((e) => e.eid));
      const logged = log.filter((e) => e.kind === "entry").map((e) => e.data.eid);
      if (planned.slice(1).sort().join() !== logged.slice().sort().join()) bad.push("the entry files are not the entries the log recorded");
      for (const e of log.filter((x) => x.kind === "entry")) {
        const ent = entriesMap[e.data.eid];
        if (ent && (ent.config_sha256 !== e.data.config_sha256 || (await sha256hex(canon(ent.config))) !== ent.config_sha256)) bad.push("entry " + e.data.eid + "'s configuration is not the one the log recorded");
      }
      if (log.some((e) => e.kind === "round_evaluated") && ev.map((e) => e.data.eid).sort().join() !== planned.slice().sort().join()) bad.push("the evaluated arms are not the planned ones");
      if ((await sha256hex(canon(roundJson.baseline))) !== log[0].data.baseline_sha256) bad.push("the baseline configuration is not the one the log fixed");
      add("ladders", "each ladder file is byte-identical to the one the log recorded when the arm was evaluated", bad.length ? "fail" : "pass", bad[0] || ev.length + " ladders, " + (planned.length - 1) + " entry file(s)");
    });
    if (log) await guard("results", "results.json is the file the log recorded", async () => {
      const r = log.find((e) => e.kind === "results");
      if (!r && !files[R + "results.json"]) { add("results", "results.json is the file the log recorded", "skip", "the round has no results yet"); return; }
      if (!r || !files[R + "results.json"]) { add("results", "results.json is the file the log recorded", "fail", "results.json and its log entry must both exist"); return; }
      const sha = await sha256hex(files[R + "results.json"]);
      results.sha = sha;
      add("results", "results.json is the file the log recorded", sha === r.data.results_sha256 ? "pass" : "fail", sha === r.data.results_sha256 ? sha.slice(0, 16) : "results.json is not the file the log recorded");
    });

    // -- the registry (also decides which key signed the round)
    let eff = pinned.slice(), roundKey = null, keyProblem = null, terms = [];
    if (files["registry.jsonl"]) await guard("registry", "the registry is intact and signed by a key you pinned", async () => {
      regRows = lines(text("registry.jsonl"));
      const w = await registryWalk(regRows);
      terms = w.terms;
      let probs = w.probs.slice();
      if (!probs.length) {
        if (!regRows.length) probs.push("the registry is empty");
        else if (!pinned.length) { add("registry", "the registry is intact and signed by a key you pinned", "skip", "no key pinned: the chain and every signature are consistent, but you have not said whose key to trust (" + regRows.length + " entries)"); }
        else if (trustedFrom(terms, pinned) === null) probs.push("the registry is signed by no key you pinned");
      }
      if (probs.length) { add("registry", "the registry is intact and signed by a key you pinned", "fail", probs[0]); regRows = null; return; }
      if (pinned.length) add("registry", "the registry is intact and signed by a key you pinned", "pass", regRows.length + " entries");
      const info = registryRounds(regRows)[rid];
      const tf = trustedFrom(terms, pinned);
      if (info && tf !== null) {
        const oSeq = nv(info.open.seq), eSeq = info.end ? nv(info.end.seq) : null;
        const tOpen = termAt(terms, oSeq), tEnd = eSeq !== null ? termAt(terms, eSeq) : null;
        const cs = tOpen ? tOpen.compromised_since : null;
        if (!tOpen || (tEnd && tEnd !== tOpen)) keyProblem = "the round was opened under one key and closed under another";
        else if (oSeq < tf) keyProblem = "the round was registered before the first key term you pinned: the earlier history is not authenticated by your pins";
        else if (cs !== null && (oSeq >= cs || (eSeq !== null && eSeq >= cs))) keyProblem = "the owner declared this key COMPROMISED from registry entry " + cs + ", and this round is at or after it";
        else roundKey = tOpen.key;
      }
      if (roundKey) eff.push(roundKey);
      verifierKeys.add(roundKey || regRows[0].pubkey);
      if (regRows.length && (new Set(regRows.map((e) => e.pubkey)).size > 1 || regRows[0].kind === "key_inception"))
        add("keys", "the verifier's key history is sound and this round was signed under ONE authenticated key", !pinned.length ? "skip" : keyProblem === null && roundKey !== null ? "pass" : "fail", (!pinned.length ? "no key pinned, so no key term can be authenticated: " : "") + (keyProblem || terms.map((t) => t.key.slice(0, 8) + "...[" + t.from_seq + ".." + (t.to_seq === null ? "now" : t.to_seq) + "]").join(" -> ")));
    });
    else add("registry", "the registry is intact and signed by a key you pinned", opts.requireRegistry === false ? "skip" : "fail", "this bundle has no registry.jsonl: nothing shows the round was registered before it ran (a bundle without one cannot pass; the Python audit's --require-registry is the default here)");

    // -- the joint seed
    if (files["joint.json"] && files["joint.revealed.json"]) await guard("joint", "the joint seed is the hash of every party's committed share and produces the round's commitment", async () => {
      jointDoc = parseJSON(text("joint.json"));
      const jr = parseJSON(text("joint.revealed.json"));
      const out = await jointProblems(jointDoc, jr, roundJson ? roundJson.commitment : undefined, opts.partyPins && opts.partyPins.length ? opts.partyPins : null);
      if (!out.probs.length && !out.usesBeacon) { jointKeys = Object.create(null); for (const c of jointDoc.parties) jointKeys[c.statement.party] = c.statement.pubkey; }
      if (out.usesBeacon) add("joint", "the joint seed is the hash of every party's committed share and produces the round's commitment", out.probs.length ? "fail" : "skip", out.probs[0] || "the parties' shares match their signed commitments, but the seed also includes a drand beacon round, which only the Python audit verifies");
      else add("joint", "the joint seed is the hash of every party's committed share and produces the round's commitment", out.probs.length ? "fail" : "pass", out.probs[0] || Object.keys(jr.shares).length + " parties" + (opts.partyPins && opts.partyPins.length ? ", party keys pinned" : " (party keys NOT pinned: the keys are only known to be self-consistent)"));
    });
    else if (files["joint.json"] || files["joint.revealed.json"]) add("joint", "the joint seed is the hash of every party's committed share", "fail", "joint.json and joint.revealed.json must both be present");

    // -- the registry's account of this round
    if (regRows && log) await guard("registered", "the registry's account matches the round: registered BEFORE it ran, arms and joint seed as registered, outcome recorded", async () => {
      const info = registryRounds(regRows)[rid];
      if (!info) { add("registered", "the registry's account matches the round: registered BEFORE it ran, arms and joint seed as registered, outcome recorded", "fail", "round " + rid + " is not in the registry"); return; }
      const bad = [];
      const o = info.open.data;
      if (o.plan_hash !== roundJson.plan_hash || o.commitment !== roundJson.commitment || o.domain !== roundJson.domain || !same(o.practice, roundJson.practice)) bad.push("the registry's open entry names a different plan, seed commitment or domain than the round");
      const arms = [{ eid: "baseline", handle: null, label: roundJson.baseline.label, spec: roundJson.baseline.agent, config_sha256: await sha256hex(canon(roundJson.baseline)) }];
      for (const e of entriesList) arms.push({ eid: e.eid, handle: e.handle, label: e.config.label, spec: e.config.agent, config_sha256: e.config_sha256 });
      if (!same(o.arms, arms)) bad.push("the arms the registry recorded at opening are not the round's arms");
      const hasJoint = o.joint_sha256 !== null && o.joint_sha256 !== undefined;
      if (hasJoint !== (jointDoc !== null) || (jointDoc !== null && o.joint_sha256 !== (await sha256hex(canon(jointDoc))))) bad.push(jointDoc !== null ? "the joint-seed record is not the one registered at opening" : "the round was registered with a joint seed but none was supplied");
      const regAt = log.findIndex((e) => e.kind === "registered" && e.data.registry_hash === info.open.hash);
      const firstEval = log.findIndex((e) => e.kind === "evaluated");
      if (regAt < 0) bad.push("the round's own log does not record this registration: it was not registered before it ran (or the registry's open entry is not the one the round saw)");
      else if (firstEval >= 0 && regAt > firstEval) bad.push("the round was registered AFTER its first arm was evaluated: not a pre-registration");
      else if (log[regAt].data.registry_pubkey !== info.open.pubkey) bad.push("the round's log names a different registry key than the registry entry");
      if (info.status === "void") bad.push("the registry says this round was VOIDED: " + (info.end.data.reason || ""));
      else if (info.status !== "closed") bad.push("the registry has no close entry for this round");
      else {
        const c = info.end.data;
        if (!log.some((e) => e.hash === c.log_head)) bad.push("the registry's closing log head is not in the round's log");
        const ev = Object.create(null);
        for (const e of log) if (e.kind === "evaluated") ev[e.data.eid] = e.data.digest;
        if (!same(c.ladder_digests, ev)) bad.push("the ladder digests the registry recorded at closing are not the round's");
        if (results.sha && c.results_sha256 !== results.sha) bad.push("the results file the registry recorded at closing is not the round's");
      }
      add("registered", "the registry's account matches the round: registered BEFORE it ran, arms and joint seed as registered, outcome recorded", bad.length ? "fail" : "pass", bad[0] || "registered at log entry " + regAt + ", before the first evaluation (entry " + firstEval + ")");
    });

    // -- black-box arms: the service key named in each ladder's header must be one you pinned (the sessions' own signatures are replayed only by the Python audit)
    if (log) await guard("service", "each black-box arm's service key is one you pinned", async () => {
      const bad = [], seen = [];
      for (const p of Object.keys(files).filter((q) => q.startsWith(R + "ladders/") && q.endsWith(".jsonl")).sort()) {
        const first = text(p).split("\n", 1)[0];
        const h = parseJSON(first);
        if (!isObj(h) || !h.mode) continue;
        const k = isObj(h.service) ? h.service.pubkey : undefined;
        seen.push(String(get1(h, "agent", "label")));
        verifierKeys.add(k);
        if (!pinned.length) continue;
        if (typeof k !== "string" || !eff.includes(k)) bad.push("the service key of arm " + String(get1(h, "agent", "label")) + " (" + String(k).slice(0, 16) + ") is not one you pinned");
      }
      if (!seen.length) return;                                      // no black-box arm: nothing to check (the white-box note is below)
      add("service", "each black-box arm's service key is one you pinned", bad.length ? "fail" : (pinned.length ? "pass" : "skip"), bad[0] || (pinned.length ? seen.join(", ") : "no key pinned"));
    });
    if (log) await guard("whitebox", "white-box arms", async () => {
      const wb = [];
      for (const p of Object.keys(files).filter((q) => q.startsWith(R + "ladders/") && q.endsWith(".jsonl")).sort()) {
        const h = parseJSON(text(p).split("\n", 1)[0]);
        if (isObj(h) && !h.mode) wb.push(String(get1(h, "agent", "label")));
      }
      if (wb.length) add("whitebox", "white-box arm(s) " + wb.join(", "), "info", "run by the verifier's own harness: consistent with the seed, but there is no per-trial signature and nothing but the verifier's word that a model produced them");
    });

    // -- the certificates
    const certPaths = Object.keys(files).filter((p) => /^certificates\/[^/]+\.json$/.test(p)).sort();
    const certs = [];
    if (!certPaths.length) add("certs", "the bundle holds at least one certificate", "fail", "no certificates/*.json");
    for (const p of certPaths) await guard("cert:" + p, "certificate " + p + " is signed by a key you pinned and bound to this round", async () => {
      const title = "certificate " + p + " is signed by a key you pinned and bound to this round";
      const doc = parseJSON(text(p));
      if (!isObj(doc) || !isObj(doc.statement) || typeof doc.signature !== "string") { add("cert:" + p, title, "fail", "not a signed certificate"); return; }
      const st = doc.statement;
      const bad = [];
      if (st.format !== CERT_FORMAT) bad.push("not a " + CERT_FORMAT);
      if (!(await statementOk(doc))) bad.push("the certificate's signature is not valid");
      const signedByPinned = eff.includes(st.pubkey);
      if (pinned.length && !signedByPinned) bad.push("the certificate is signed by " + String(st.pubkey).slice(0, 16) + ", which is not a key you pinned (nor the one the registry authenticates for this round)");
      if (st.round.id !== rid) bad.push("the certificate is for round " + st.round.id);
      if (roundJson && (st.round.commitment !== roundJson.commitment || st.round.plan_hash !== roundJson.plan_hash || !same(st.round.practice, roundJson.practice) || st.round.domain !== roundJson.domain)) bad.push("the certificate's plan, commitment or domain is not the round's");
      if (log) {
        const k = nv(st.round.log_entries);
        if (!(k >= 1 && k <= log.length) || log[k - 1].hash !== st.round.log_head) bad.push("the certificate's log head is not the round's log at that length");
      }
      const eid = st.candidate.eid;
      const lf = R + "ladders/" + eid + ".jsonl", bf = R + "ladders/baseline.jsonl";
      if (!files[lf] || !files[bf]) bad.push("the ladders it compares are not in the bundle");
      else {
        if ((await sha256hex(files[lf])) !== st.candidate.ladder_sha256) bad.push("the candidate ladder is not the one the certificate names");
        if ((await sha256hex(files[bf])) !== st.baseline.ladder_sha256) bad.push("the baseline ladder is not the one the certificate names");
      }
      if (log) {
        const ev = log.filter((e) => e.kind === "evaluated");
        const e1 = ev.find((e) => e.data.eid === eid), e0 = ev.find((e) => e.data.eid === "baseline");
        if (!e1 || e1.data.digest !== st.candidate.digest || e1.data.ladder_sha256 !== st.candidate.ladder_sha256) bad.push("the candidate's digest is not what the log recorded");
        if (!e0 || e0.data.digest !== st.baseline.digest) bad.push("the baseline's digest is not what the log recorded");
        const ent = entriesMap[eid];
        if (ent && ent.config_sha256 !== st.candidate.config_sha256) bad.push("the candidate's configuration is not the entry's");
      }
      certs.push({ path: p, st, signedBy: st.pubkey, pinnedSigner: signedByPinned });
      if (typeof st.pubkey === "string") verifierKeys.add(st.pubkey);
      add("cert:" + p, title, bad.length ? "fail" : (pinned.length ? "pass" : "skip"), bad[0] || (pinned.length ? "signed by " + st.pubkey.slice(0, 16) : "the signature and every binding hold, but no key is pinned, so this only shows who signed (" + st.pubkey.slice(0, 16) + ")"));
    });

    // -- disclosure: the other rounds this candidate configuration was entered in (what a reader needs to judge one certificate; omission by the verifier is invisible here)
    if (regRows && certs.length) await guard("disclosure", "disclosure: other rounds this candidate configuration was entered in", async () => {
      const all = registryRounds(regRows);
      for (const ch of Array.from(new Set(certs.map((c) => c.st.candidate.config_sha256))).sort()) {
        const others = [];
        for (const r of Object.keys(all).sort()) {
          if (r === rid) continue;
          for (const a of all[r].open.data.arms) if (a.config_sha256 === ch) others.push(r + " (" + all[r].status + ")");
        }
        add("disclosure", "disclosure: other rounds this candidate configuration was entered in", "info", others.length ? others.length + ": " + others.slice(0, 8).join(", ") : "none (only the rounds this registry holds: a verifier that ran rounds it never registered is not visible here)");
      }
    });

    // -- key separation (needs you to say which joint-seed party is the verifier)
    if (opts.verifierParty && jointKeys) await guard("separation", "key separation", async () => {
      const vk = jointKeys[opts.verifierParty];
      const others = Object.keys(jointKeys).filter((p) => p !== opts.verifierParty);
      add("verifier-share", "the verifier's share was committed by a key that also signed this round's sessions, certificates and registry", vk && verifierKeys.has(vk) ? "pass" : "fail", String(vk).slice(0, 16));
      const clash = others.filter((p) => verifierKeys.has(jointKeys[p])).sort();
      add("separation", "no OTHER party's key is a verifier key (key separation: operator, vendors and verifier are different keys)", clash.length ? "fail" : "pass", clash.join(", "));
    });
    else if (jointKeys) add("separation", "key separation between the joint-seed parties and the verifier", "skip", "you did not say which party is the verifier, so this was not checked");

    // -- evidence the bundle carries that this page does not verify
    if (Object.keys(files).some((p) => p.startsWith("log/"))) add("evidence-log", "the evidence transparency log in this bundle", "skip", "its inclusion proofs, consistency proofs and witness timelines are verified only by the Python audit (--require-log); the order of commitments before registration is therefore not checked here");
    if (files["tee/evidence.json"]) add("tee", "the hardware attestation in this bundle", "skip", "verified only by the Python audit, against an image measurement you build yourself (--tee-pcr)");

    const result = finish(checks, pinned, opts, ctx, certs);
    return result;
  }

  function finish(checks, pinned, opts, ctx, certs) {
    const fail = checks.filter((c) => c.status === "fail");
    const pass = checks.filter((c) => c.status === "pass");
    const skip = checks.filter((c) => c.status === "skip");
    let state, headline;
    if (fail.length) { state = "fail"; headline = "FAILED: " + fail[0].title + (fail[0].detail ? " (" + fail[0].detail + ")" : ""); }
    else if (!pinned.length) { state = "unpinned"; headline = "CONSISTENT, BUT NOT AUTHENTICATED: nothing was checked against a key you trust, because none was pinned."; }
    else if (opts.keySource === "site") { state = "pinned-by-site"; headline = "PASSED, but the key was supplied by this page, so this only shows the bundle is consistent and signed by that key. It does not show you can trust whoever holds it."; }
    else if (opts.keySource === "link") { state = "pinned-by-link"; headline = "PASSED against the key in the link you followed. Confirm that key against the verifier's own publication before relying on it."; }
    else { state = "pass"; headline = "PASSED every check this page can run, against the key you supplied."; }
    // evidence the bundle CARRIES but this page cannot verify (a beacon in the seed, the evidence log, hardware attestation): the bundle's own claims about those are unchecked here, so a plain pass would overstate
    const carried = skip.filter((c) => c.id === "joint" || c.id === "evidence-log" || c.id === "tee");
    if (carried.length && !fail.length) {
      const note = "This bundle carries evidence this page cannot check: " + carried.map((c) => (c.id === "joint" ? "the joint seed includes a drand beacon round" : c.title)).join("; ") + ". Run the Python audit for those.";
      if (state === "pass") { state = "partial"; headline = "PASSED what this page can check. " + note; } else headline += " " + note;
    }
    if (skip.length && !fail.length && state !== "partial") headline += " (" + skip.length + " check" + (skip.length === 1 ? " was" : "s were") + " skipped: see below.)";
    return { state, headline, round: ctx.rid, checks, counts: { pass: pass.length, fail: fail.length, skip: skip.length }, notCheckedHere: NOT_CHECKED_HERE, certificates: certs || [], pinned };
  }

  // ---------------------------------------------------------------- loading

  async function loadFromBase(baseUrl, fetchFn) {
    const f = fetchFn || (typeof fetch !== "undefined" ? fetch : null);
    if (!f) throw new Error("no fetch available");
    const base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
    const get = async (p) => {
      const r = await f(base + p.split("/").map(encodeURIComponent).join("/"));       // each segment encoded: a listed name such as "%2e%2e" or "a?b" must not steer the request
      if (!r.ok) throw new Error("could not fetch " + p + " (HTTP " + r.status + ")");
      return new Uint8Array(await r.arrayBuffer());
    };
    const files = Object.create(null);
    files["BUNDLE.json"] = await get("BUNDLE.json");
    const m = parseJSON(new TextDecoder().decode(files["BUNDLE.json"]));
    if (!isObj(m) || !isObj(m.files)) throw new Error("BUNDLE.json is not a manifest");
    const names = Object.keys(m.files);
    if (names.length > MAX_FILES) throw new Error("the manifest lists " + names.length + " files; this page reads at most " + MAX_FILES + " (use the Python audit for a bundle this large)");
    let total = 0;
    for (const p of names) {
      if (!safePath(p)) throw new Error("the manifest lists an unsafe path");
      files[p] = await get(p);
      total += files[p].length;
      if (total > MAX_BYTES) throw new Error("the bundle is larger than " + (MAX_BYTES >> 20) + " MB; this page will not read more (use the Python audit)");
    }
    return files;
  }

  return { verifyBundle, loadFromBase, parseJSON, canon, sha256hex, ed25519Verify, statementOk, hexToBytes, bytesToHex, registryWalk, NOT_CHECKED_HERE, Num };
});
