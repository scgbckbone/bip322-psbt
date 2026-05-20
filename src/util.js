import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';

export function hash160(data) {
  return ripemd160(sha256(data));
}

export function hash256(data) {
  return sha256(sha256(data));
}

export function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(s) {
  if (s.length % 2) throw new Error('odd hex length');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function u8(n) {
  return new Uint8Array([n & 0xff]);
}

export function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

export function i32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, n | 0, true);
  return b;
}

export function u64le(n) {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  const bn = BigInt(n);
  v.setBigUint64(0, bn, true);
  return b;
}

export function varint(n) {
  if (n < 0) throw new Error('negative varint');
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    new DataView(b.buffer).setUint16(1, n, true);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    new DataView(b.buffer).setUint32(1, n, true);
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = 0xff;
  new DataView(b.buffer).setBigUint64(1, BigInt(n), true);
  return b;
}

export function varBytes(b) {
  return concat(varint(b.length), b);
}

export function utf8(s) {
  return new TextEncoder().encode(s);
}

export function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
