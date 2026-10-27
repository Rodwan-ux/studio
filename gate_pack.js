// 1325: the PLAY gate's pack tool — turns a web build into the sealed build the PLAY tab of the studio dashboard opens (1453).
//
// The player's code is the key: PBKDF2-SHA256(code, salt) gives 64 bytes — the first 32 name the code's entry (HMAC "id"),
// the last 32 open that entry, which holds the one game key (AES-256-GCM). Neither the codes nor the game key are stored
// in the clear. The game file is cut into chunks, each sealed on its own (AES-GCM, IV = base + chunk number), and the
// sealed stream is split into parts under the GitHub Pages file limit; the gate opens them chunk by chunk in memory.
// 1419: each chunk is deflated before it is sealed (a sealed file cannot be compressed by the server any more), so the
// chunks differ in length - gate.json lists them (lens); the gate inflates each one after opening it.
// 1417: each music track beside the game (music/) is sealed whole with its own IV, the gate opens one when the game
// plays it; the engine files (index.js, index.wasm, the audio worklets) are copied as they are.
// 1486: every seal makes a new game key, kept beside the sealed folder (<out>/../gate.key, never in the published
// folder), so a dropped code opens no later build; a patch of that build is sealed with that build's key.
//
//   node gate_pack.js --build <web build folder> --out <dir> [--codes <build_codes.cfg>] [--key <game key file>]
//                     [--owner-key <file>] [--iter 200000] [--chunk 4194304] [--part 94371840]
//
// --codes: [codes] and [days] of build_codes.cfg (1483: the one code list, never in the exported game). Before anything
// is sealed the list goes to the Codes tab of the studio sheet (action studio_codes, the owner key of the studio CLI,
// the address = [build] sheet_url of build_config.cfg) - the sheet is what the game asks; no sheet answer, no seal.
// 1494: the codes BLOCKED in the Codes tab (its answer OK|code,code) get no entry in the seal.
//
// 1455: node gate_pack.js --patch <patch.pck> --out <sealed build dir> [--key file]
// seals a Godot patch pack (the files changed since the build) whole - deflated, then AES-GCM with the same game key - as
// patch.enc beside the parts and names it in that gate.json (patch = {iv, size, sha256}); the parts are not touched.
const fs = require("fs"), path = require("path"), crypto = require("crypto"), zlib = require("zlib");

const arg = (n, d) => { const i = process.argv.indexOf("--" + n); return i >= 0 ? process.argv[i + 1] : d; };
const BUILD = arg("build"), OUT = arg("out"), PATCH = arg("patch");
const KEY_FILE = OUT && arg("key", path.join(OUT, "..", "gate.key"));   // 1486: the build's own key, beside its sealed folder
if (PATCH && OUT) {
  const key = fs.readFileSync(KEY_FILE);
  const meta = JSON.parse(fs.readFileSync(path.join(OUT, "gate.json"), "utf8"));
  const plain = fs.readFileSync(PATCH), iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", key, iv);
  fs.writeFileSync(path.join(OUT, "patch.enc"), Buffer.concat([c.update(zlib.deflateRawSync(plain, { level: 9 })), c.final(), c.getAuthTag()]));
  meta.patch = { iv: iv.toString("base64"), size: plain.length, sha256: crypto.createHash("sha256").update(plain).digest("hex") };
  fs.writeFileSync(path.join(OUT, "gate.json"), JSON.stringify(meta));
  console.log("patch: %d KB sealed -> %s", Math.round(plain.length / 1024), OUT);
  process.exit(0);
}
const ROOT = path.join(__dirname, "..", "..");
const CODES = arg("codes", path.join(ROOT, "build_codes.cfg"));
const OWNER_KEY = arg("owner-key", path.join(require("os").homedir(), ".claude", "hooks", "studio_owner_key.txt"));
const ITER = +arg("iter", 200000), CHUNK = +arg("chunk", 4 * 1024 * 1024), PART = +arg("part", 90 * 1024 * 1024);
const ENGINE = ["index.js", "index.wasm", "index.side.wasm", "index.audio.worklet.js", "index.audio.position.worklet.js"];   // side.wasm: a build with GDExtension support
// 1598: --code-env NAME = one code from that environment variable (PIXEL CULTURES' sealed build on GitHub Actions) - no
// codes file, nothing sent to the studio
const ONE_CODE = arg("code-env") ? String(process.env[arg("code-env")] || "").trim().toLowerCase() : "";
if (arg("code-env") && !ONE_CODE) { console.error("no code in " + arg("code-env")); process.exit(2); }
if (!BUILD || !OUT) { console.error("usage: node gate_pack.js --build <web build folder> --out <dir> [--codes cfg] [--key file]"); process.exit(2); }

// a section of a Godot cfg as {key: value} (quotes off)
function readSection(p, name) {
  let sec = "", out = {};
  for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
    const s = line.match(/^\[(.+)\]\s*$/); if (s) { sec = s[1]; continue; }
    const k = line.match(/^([^=;#\s]+)\s*=\s*(.*)$/);
    if (sec === name && k) out[k[1].trim().toLowerCase()] = k[2].trim().replace(/^"(.*)"$/, "$1");
  }
  return out;
}
const codeList = ONE_CODE ? { [ONE_CODE]: "" } : readSection(CODES, "codes"), dayList = ONE_CODE ? {} : readSection(CODES, "days");

// 1483: the list into the Codes tab first (what the game asks); no answer = nothing sealed
async function syncCodes() {
  const url = readSection(path.join(ROOT, "build_config.cfg"), "build").sheet_url;
  const codes = Object.keys(codeList).map((c) => ({ code: c, perms: codeList[c].split(",").map((x) => x.trim()).filter(Boolean), days: +dayList[c] || 0 }));
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ action: "studio_codes", k: fs.readFileSync(OWNER_KEY, "utf8").trim(), codes }) });
  const text = (await res.text()).trim(), [ok, list = ""] = text.split("|");
  if (ok !== "OK") throw new Error("the Codes tab did not take the codes: " + text.slice(0, 200));
  const blocked = list.split(",").filter(Boolean);
  console.log("codes: %d sent to the Codes tab, %d blocked there", codes.length, blocked.length);
  return blocked;
}

(async () => {
fs.rmSync(OUT, { recursive: true, force: true });   // a failed sync leaves no gate.json behind
const blocked = ONE_CODE ? [] : await syncCodes();

// 1486: a new game key for every seal - the build's own, beside its sealed folder
const gameKey = crypto.randomBytes(32);
fs.writeFileSync(KEY_FILE, gameKey);

fs.mkdirSync(path.join(OUT, "music"), { recursive: true });
const plain = fs.readFileSync(path.join(BUILD, "index.pck")), base = crypto.randomBytes(8);
const sha = crypto.createHash("sha256").update(plain).digest("hex");

// the sealed stream: chunk after chunk (deflated data + 16-byte tag), cut into parts
const parts = [], lens = [];
let part = [], partLen = 0;
const flush = () => { const name = "game." + parts.length + ".enc"; fs.writeFileSync(path.join(OUT, name), Buffer.concat(part)); parts.push(name); part = []; partLen = 0; };
for (let i = 0, n = 0; i < plain.length; i += CHUNK, n++) {
  const iv = Buffer.concat([base, Buffer.from([n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255])]);
  const c = crypto.createCipheriv("aes-256-gcm", gameKey, iv);
  const sealed = Buffer.concat([c.update(zlib.deflateRawSync(plain.subarray(i, i + CHUNK), { level: 9 })), c.final(), c.getAuthTag()]);
  if (partLen && partLen + sealed.length > PART) flush();
  part.push(sealed); partLen += sealed.length; lens.push(sealed.length);
}
if (part.length) flush();

// 1417: the music, one sealed file per track (file name -> its IV)
const music = {}, mdir = path.join(BUILD, "music");
let mbytes = 0;
if (fs.existsSync(mdir)) for (const f of fs.readdirSync(mdir)) {
  const data = fs.readFileSync(path.join(mdir, f)), iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", gameKey, iv);
  fs.writeFileSync(path.join(OUT, "music", f + ".enc"), Buffer.concat([c.update(data), c.final(), c.getAuthTag()]));
  music[f] = iv.toString("base64"); mbytes += data.length;
}
for (const f of ENGINE) if (fs.existsSync(path.join(BUILD, f))) fs.copyFileSync(path.join(BUILD, f), path.join(OUT, f));

// one entry per code
const salt = crypto.randomBytes(16), keys = {};
for (const code of Object.keys(codeList).filter((c) => !blocked.includes(c))) {
  const bits = crypto.pbkdf2Sync(code, salt, ITER, 64, "sha256");
  const id = crypto.createHmac("sha256", bits.subarray(0, 32)).update("id").digest("hex").slice(0, 16);
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", bits.subarray(32), iv);
  keys[id] = { iv: iv.toString("base64"), key: Buffer.concat([c.update(gameKey), c.final(), c.getAuthTag()]).toString("base64") };
}

// the build's GODOT_CONFIG, so the gate can start the engine
const m = fs.readFileSync(path.join(BUILD, "index.html"), "utf8").match(/const GODOT_CONFIG = (\{.*?\});/);
if (!m) throw new Error("no GODOT_CONFIG in the build's index.html");
const godot = JSON.parse(m[1]); delete godot.fileSizes;

// 1598: the GDExtension libraries are the game's own code - each sealed whole (file name -> its IV), never copied plain
const libs = {};
for (const f of godot.gdextensionLibs || []) {
  const data = fs.readFileSync(path.join(BUILD, f)), iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", gameKey, iv);
  fs.mkdirSync(path.dirname(path.join(OUT, f)), { recursive: true });
  fs.writeFileSync(path.join(OUT, f + ".enc"), Buffer.concat([c.update(data), c.final(), c.getAuthTag()]));
  libs[f] = iv.toString("base64");
}

const meta = { v: 3, iter: ITER, salt: salt.toString("base64"), iv: base.toString("base64"), chunk: CHUNK, size: plain.length,
  sha256: sha, parts, lens, music, keys, godot, libs };
fs.writeFileSync(path.join(OUT, "gate.json"), JSON.stringify(meta));
console.log("gate: %d MB (%d MB sealed) in %d parts, %d music tracks (%d MB), %d codes -> %s", (plain.length / 1048576).toFixed(1),
  (lens.reduce((a, b) => a + b, 0) / 1048576).toFixed(1), parts.length,
  Object.keys(music).length, (mbytes / 1048576).toFixed(1), Object.keys(keys).length, OUT);
})().catch((e) => { console.error(String(e && e.message || e)); process.exit(1); });
