// 1876: the PLAY tab's desktop build, in the tester's browser: the code opens the sealed exe and game pack, the code goes
// into the exe's slot, a zip of both comes out. Nothing is sent anywhere: the code stays here.
const SLOT_MARK = "PF_SLOT_EMPTY_7c1e94b2a6d34f08";   // = loader.gd
const SLOT_SECRET = "pf-slot-3a91d7c4e0b24c6f";       // = loader.gd: hides the code in the exe, the server decides
const SLOT_SIZE = 256;
const enc = new TextEncoder();
const bytes64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (a) => Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");

async function inflate(data) {
  const s = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

// The whole sealed stream into one buffer; say(done, all) tells the progress.
async function openParts(meta, key, base, get, say) {
  const out = new Uint8Array(meta.size), ivBase = bytes64(meta.iv);
  let n = 0, at = 0;
  for (const name of meta.parts) {
    const part = new Uint8Array(await (await get(base + name + "?v=" + meta.sha256.slice(0, 12))).arrayBuffer());
    let off = 0;
    while (off < part.length) {
      const iv = new Uint8Array(12);
      iv.set(ivBase);
      new DataView(iv.buffer).setUint32(8, n);
      const plain = await inflate(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, part.subarray(off, off + meta.lens[n]))));
      out.set(plain, at);
      at += plain.length;
      off += meta.lens[n];
      n++;
      if (say) say(at, meta.size);
    }
  }
  return out;
}

async function slotStream(salt, length) {
  const out = new Uint8Array(length);
  for (let i = 0, at = 0; at < length; i++) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(SLOT_SECRET + hex(salt) + i)));
    out.set(h.subarray(0, Math.min(32, length - at)), at);
    at += 32;
  }
  return out;
}

// The code into the exe's slot, in place: the exe keeps its length, its pack stays valid.
async function writeSlot(exe, code) {
  const mark = enc.encode(SLOT_MARK);
  let at = -1;
  outer: for (let i = exe.length - mark.length; i >= 0; i--) {
    if (exe[i] !== mark[0]) continue;
    for (let j = 1; j < mark.length; j++) if (exe[i + j] !== mark[j]) continue outer;
    at = i;
    break;
  }
  if (at < 0) throw new Error("NO SLOT IN THE EXE");
  const salt = crypto.getRandomValues(new Uint8Array(16)), body = new Uint8Array(SLOT_SIZE - 16);
  body.set(enc.encode("PF1|" + code));
  const stream = await slotStream(salt, body.length);
  for (let i = 0; i < body.length; i++) body[i] ^= stream[i];
  exe.set(salt, at);
  exe.set(body, at + 16);
}

const CRC = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(a) {
  let c = -1;
  for (let i = 0; i < a.length; i++) c = CRC[(c ^ a[i]) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// A zip without compression: the sealed pack does not shrink anyway.
function zip(files) {
  const blocks = [], central = [];
  let off = 0;
  for (const f of files) {
    const name = enc.encode(f.name), crc = crc32(f.data);
    const head = new DataView(new ArrayBuffer(30));
    head.setUint32(0, 0x04034b50, true); head.setUint16(4, 20, true); head.setUint16(6, 0x0800, true);
    head.setUint32(14, crc, true); head.setUint32(18, f.data.length, true); head.setUint32(22, f.data.length, true); head.setUint16(26, name.length, true);
    blocks.push(new Uint8Array(head.buffer), name, f.data);
    const cen = new DataView(new ArrayBuffer(46));
    cen.setUint32(0, 0x02014b50, true); cen.setUint16(4, 20, true); cen.setUint16(6, 20, true); cen.setUint16(8, 0x0800, true);
    cen.setUint32(16, crc, true); cen.setUint32(20, f.data.length, true); cen.setUint32(24, f.data.length, true); cen.setUint16(28, name.length, true); cen.setUint32(42, off, true);
    central.push(new Uint8Array(cen.buffer), name);
    off += 30 + name.length + f.data.length;
  }
  const size = central.reduce((a, b) => a + b.length, 0), end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true); end.setUint32(12, size, true); end.setUint32(16, off, true);
  return new Blob([...blocks, ...central, new Uint8Array(end.buffer)], { type: "application/zip" });
}

// The opened game key -> the zip of the exe (with the code in its slot) and the game pack.
async function desktopZip(meta, key, code, base, get, say) {
  const all = await openParts(meta, key, base, get, say);
  const files = [];
  let at = 0;
  for (const f of meta.files) {
    files.push({ name: f.name, data: all.subarray(at, at + f.size) });
    at += f.size;
  }
  await writeSlot(files[0].data, code);
  return zip(files);
}
if (typeof module !== "undefined") module.exports = { desktopZip };
