import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  publicEncrypt,
  constants,
  randomBytes,
  randomInt,
} from "node:crypto";
import { gunzipSync } from "node:zlib";
import { BASE62, EAPI_KEY, IV, LINUX_API_KEY, PRESET_KEY, PUBLIC_KEY } from "./config";

/**
 * Netease API 加解密层
 *
 * - 加密方式：weapi（web 端）、linuxapi（Linux 客户端）、eapi（桌面/移动客户端）、xeapi（反爬）
 * - 各对应对称密钥 + RSA 公钥；全部用 Node 原生 node:crypto 实现，不引第三方加密库
 */

/** AES 加密 */
export const aesEncrypt = (
  text: string | Buffer,
  mode: "cbc" | "ecb",
  key: string,
  iv: string,
  format: "base64" | "hex" = "base64",
): string => {
  const algorithm = mode === "cbc" ? "aes-128-cbc" : "aes-128-ecb";
  const ivBuf = mode === "cbc" ? Buffer.from(iv, "utf8") : Buffer.alloc(0);
  const cipher = createCipheriv(algorithm, Buffer.from(key, "utf8"), ivBuf);
  const encrypted = Buffer.concat([
    cipher.update(typeof text === "string" ? Buffer.from(text, "utf8") : text),
    cipher.final(),
  ]);
  return format === "base64"
    ? encrypted.toString("base64")
    : encrypted.toString("hex").toUpperCase();
};

/** AES 解密 */
export const aesDecrypt = (
  ciphertext: string,
  key: string,
  format: "base64" | "hex" = "base64",
): Buffer => {
  const decipher = createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), Buffer.alloc(0));
  const input = Buffer.from(ciphertext, format);
  return Buffer.concat([decipher.update(input), decipher.final()]);
};

/** weapi 裸 RSA */
export const rsaEncrypt = (str: string, publicKey: string = PUBLIC_KEY): string => {
  const buffer = Buffer.alloc(128);
  const data = Buffer.from(str, "utf8");
  data.copy(buffer, 128 - data.length);
  const encrypted = publicEncrypt({ key: publicKey, padding: constants.RSA_NO_PADDING }, buffer);
  return encrypted.toString("hex");
};

/** weapi 加密 */
export const weapi = (object: unknown): { params: string; encSecKey: string } => {
  const text = JSON.stringify(object);
  let secretKey = "";
  for (let i = 0; i < 16; i++) {
    secretKey += BASE62.charAt(randomInt(0, 62));
  }
  const first = aesEncrypt(text, "cbc", PRESET_KEY, IV);
  const params = aesEncrypt(first, "cbc", secretKey, IV);
  const encSecKey = rsaEncrypt(secretKey.split("").reverse().join(""));
  return { params, encSecKey };
};

/** linuxapi 加密 */
export const linuxapi = (object: unknown): { eparams: string } => {
  const text = JSON.stringify(object);
  return { eparams: aesEncrypt(text, "ecb", LINUX_API_KEY, "", "hex") };
};

/**
 * 递归按键名排序 JSON 对象。
 * Swift JSONSerialization(options: [.sortedKeys]) 会对对象键按字典序稳定排序；
 * 为了让 Node 侧 EAPI 明文与 MeloX iOS 完全一致，这里显式复现该行为。
 */
const sortJsonKeys = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sortJsonKeys);
  if (!value || typeof value !== "object") return value;

  const object = value as Record<string, unknown>;
  return Object.keys(object)
    .sort()
    .reduce<Record<string, unknown>>((result, key) => {
      result[key] = sortJsonKeys(object[key]);
      return result;
    }, {});
};

/** eapi 加密 */
export const eapi = (url: string, object: unknown): { params: string } => {
  const normalized = typeof object === "object" && object !== null ? sortJsonKeys(object) : object;
  const text = typeof normalized === "object" ? JSON.stringify(normalized) : String(normalized);
  const message = `nobody${url}use${text}md5forencrypt`;
  const digest = createHash("md5").update(message).digest("hex");
  const data = `${url}-36cd479b6b5-${text}-36cd479b6b5-${digest}`;
  return { params: aesEncrypt(data, "ecb", EAPI_KEY, "", "hex") };
};

/** eapi 响应解密 */
export const eapiResDecrypt = (encryptedHex: string, aeapi = false): unknown => {
  try {
    const decrypted = aesDecrypt(encryptedHex, EAPI_KEY, "hex");
    if (aeapi) {
      const decompressed = gunzipSync(decrypted);
      return JSON.parse(decompressed.toString("utf8"));
    }
    return JSON.parse(decrypted.toString("utf8"));
  } catch {
    return null;
  }
};

/** eapi 请求体解密 */
export const eapiReqDecrypt = (encryptedHex: string): { url: string; data: unknown } | null => {
  const text = aesDecrypt(encryptedHex, EAPI_KEY, "hex").toString("utf8");
  const match = text.match(/(.*?)-36cd479b6b5-(.*?)-36cd479b6b5-(.*)/);
  if (!match) return null;
  return { url: match[1], data: JSON.parse(match[2]) };
};

// ---- xeapi（反爬加密）----

/** xeapi 固定对称密钥（AES-256-ECB） */
const XEAPI_STATIC_KEY = Buffer.from(
  "ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84",
  "hex",
);
/** xeapi 签名密钥（HMAC-SHA256，按字符串原样作为 key，不解码） */
const XEAPI_SIGN_KEY =
  "mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==";
/** X25519 公钥的 RFC 8410 SPKI 固定前缀 */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface XeapiPublicKey {
  version: string;
  publicKey: string;
  sk?: string;
  [key: string]: unknown;
}

export interface XeapiOptions {
  publicKeyState: XeapiPublicKey;
  sessionId?: string;
  sessionKey?: string;
  os?: string;
  method?: string;
  contentType?: string;
}

const aesEcbEncrypt = (key: Buffer, plaintext: Buffer): Buffer => {
  const cipher = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
};

const aesEcbDecrypt = (key: Buffer, ciphertext: Buffer): Buffer => {
  const decipher = createDecipheriv(`aes-${key.length * 8}-ecb`, key, null);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
};

const createX25519PublicKey = (raw: Buffer) =>
  createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });

const deriveX25519AesKey = (sharedSecret: Buffer, ephemeralPublicKey: Buffer): Buffer => {
  const prk = createHmac("sha256", Buffer.alloc(32))
    .update(sharedSecret.length ? sharedSecret : Buffer.alloc(32))
    .digest();
  return createHmac("sha256", prk)
    .update(Buffer.concat([ephemeralPublicKey, Buffer.from([1])]))
    .digest()
    .subarray(0, 16);
};

export const xeapiSign = (timestamp: string | number, nonce: string): string =>
  createHmac("sha256", XEAPI_SIGN_KEY)
    .update(String(timestamp) + nonce)
    .digest("base64");

const xeapiMidTransform = (ciphertext: Buffer): Buffer => {
  const random = randomBytes(16);
  const xored = Buffer.alloc(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i++) xored[i] = ciphertext[i] ^ random[i & 0x0f];
  const b64 = Buffer.from(xored.toString("base64"));
  const rot = b64.length ? (random[0] & 0x0f) % b64.length : 0;
  return Buffer.concat([random, b64.subarray(rot), b64.subarray(0, rot)]);
};

const xeapiEncryptS = (dynamicKey: Buffer, publicKeyState: XeapiPublicKey, os: string): Buffer => {
  const peerKey = createX25519PublicKey(Buffer.from(publicKeyState.publicKey, "base64"));
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const ephemeralRaw = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  const sharedSecret = diffieHellman({ privateKey, publicKey: peerKey });
  const aesKey = deriveX25519AesKey(sharedSecret, ephemeralRaw);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-128-gcm", aesKey, iv);
  const plaintext = Buffer.from(
    `${dynamicKey.toString("base64")}|${os}|${publicKeyState.sk || ""}`,
  );
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ephemeralRaw, iv, encrypted, cipher.getAuthTag()]);
};

const buildXeapiPlaintext = (
  uri: string,
  data: Record<string, unknown>,
  options: XeapiOptions,
): string => {
  const fields: Record<string, string> = {};
  const contentType = options.contentType || "application/x-www-form-urlencoded;charset=utf-8";
  if (contentType.split(";", 1)[0].toLowerCase() !== "application/x-www-form-urlencoded") {
    fields.contentType = contentType;
  }
  fields.body = Buffer.from(new URLSearchParams(data as Record<string, string>).toString()).toString("base64");
  fields.queryString = "e_r=true";
  fields.method = options.method || "POST";
  return JSON.stringify(fields);
};

export const xeapi = (
  uri: string,
  data: Record<string, unknown>,
  options: XeapiOptions,
): Record<string, string> => {
  const plaintext = Buffer.from(buildXeapiPlaintext(uri, data, options));
  const dynamicKey = options.sessionKey
    ? Buffer.from(options.sessionKey, "base64")
    : randomBytes(16);
  const staticEncrypted = aesEcbEncrypt(XEAPI_STATIC_KEY, plaintext);
  const mid = xeapiMidTransform(staticEncrypted);
  const b = aesEcbEncrypt(dynamicKey, mid);
  const s = xeapiEncryptS(dynamicKey, options.publicKeyState, options.os || "android");
  const r = aesEcbEncrypt(
    XEAPI_STATIC_KEY,
    Buffer.from(`${options.publicKeyState.version}|${options.sessionKey ? options.sessionId || "" : ""}`),
  );
  return {
    B: b.toString("base64"),
    S: s.toString("base64"),
    R: r.toString("base64"),
  };
};

const stripOptionalGzip = (data: Buffer): Buffer => {
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) return gunzipSync(data);
  return data;
};

export const xeapiResDecrypt = (data: Buffer): unknown => {
  try {
    return JSON.parse(stripOptionalGzip(data).toString("utf8"));
  } catch {
    try {
      return JSON.parse(gunzipSync(data).toString("utf8"));
    } catch {
      return null;
    }
  }
};
