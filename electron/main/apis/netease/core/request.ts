/**
 * Netease API 请求层
 *
 * 核心职责：根据加密方式（weapi / linuxapi / eapi / api / xeapi）构造 URL、headers、form body，
 * 处理 cookie 合并、响应解密、状态码归一化
 */

import { randomBytes } from "node:crypto";
import {
  API_DOMAIN,
  DOMAIN,
  ENCRYPT_RESPONSE,
  OS_MAP,
  SPECIAL_STATUS_CODES,
  UA_MAP,
  XEAPI_DOMAIN,
  type CryptoMode,
} from "./config";
import { cookieObjToString, cookieToJson } from "./cookie";
import * as encrypt from "./crypto";
import { getAnonymousToken, getDeviceId } from "./device";
import { ensureXeapiKey, getXeapiSession, updateXeapiSession } from "./xeapi";
import { fetchWithProxy } from "@main/utils/proxy";

/** 调用方传入的可选参数 */
export interface RequestOptions {
  /** 加密方式；省略时依据路径默认规则，详见 createRequest */
  crypto?: CryptoMode | "";
  /** 预注入 cookie，可为字符串或对象 */
  cookie?: string | Record<string, string>;
  /** 自定义 User-Agent */
  ua?: string;
  /** 自定义 Referer/域名覆盖 */
  domain?: string;
  /** 真实 IP（X-Real-IP / X-Forwarded-For） */
  realIP?: string;
  ip?: string;
  /** 是否让服务端加密响应体（仅 weapi/eapi 有效） */
  e_r?: boolean;
  /** 强制附加 anti-cheat token（暂未启用） */
  checkToken?: boolean;
}

/** 响应统一结构 */
export interface RequestResponse {
  status: number;
  body: Record<string, unknown>;
  cookie: string[];
}

/** 非 200 响应抛出的错误 */
export class NeteaseRequestError extends Error {
  readonly response: RequestResponse;
  constructor(response: RequestResponse) {
    const body = response.body as { code?: number | string; msg?: string; message?: string };
    const code = body?.code ?? response.status;
    const msg = body?.msg ?? body?.message ?? "";
    super(msg ? `netease ${code}: ${msg}` : `netease ${code}`);
    this.name = "NeteaseRequestError";
    this.response = response;
  }
}

interface NeteaseBody {
  code?: number | string;
  [key: string]: unknown;
}

/** weapi 专用 CSRF：从 cookie 中取 __csrf */
const csrfFrom = (cookie: Record<string, string>): string => cookie["__csrf"] || "";

/** macOS 客户端日志接口需要桌面浏览器 UA */
const OSX_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/** 与 unblockneteasemusic 一致：路径包含 "url" 的请求（播放/下载地址等）替换请求头 */
const URL_PATH_KEYWORD = "url";

/** 返回 URL 的请求专用 Cookie（模拟 unblockneteasemusic 的 NETEASE_COOKIE，硬编码） */
const NETEASE_COOKIE =
  "ntes_kaola_ad=1; __csrf=8d67b6f0481f86cde9fddf43708b79d3; EVNSM=1.0.0; NMCID=wabmka.1785335019000.01.3; NMDI=Q1NKTQcBDAA7hVogCVEQS2hWg%2BpoAAAA7NuPUAIzCNutHNcg0iqegquZC7HnWpR7C2gydhM1X4bG2Ae5nSGmW6WKYY9zr6hfmt4QpKgGyA9i2qBwniR%2F%2FyUM9khG9VCwdCKFszc7rZcLBG5cYIPgR9zR9XP99CNQluh1YgHYcjM%3D; URS_APPID=A3D58FFD6065DC60B1247F56D57C39316EA1D3C5D65C3766EFB4A38A7EC0CA6234708886D92A370536AFC2F8BCB0E7588D231F295379E2C2CF217DF79226B5F406253E5893B7DC3FABF2925C7F7E5BE4614EE170EB2913B01F04238ADB59B052; appkey=IuRPVVmc3WWul9fT; appver=9.5.60; buildver=7150; caid={\"lastIyunId\":\"8a19951c0b8445e0d3a06c412c5270d6\",\"iyunId\":\"670e71e0707c8ef014d54ccf7c2606eb\",\"iyunVersion\":\"20260506\",\"lastIyunVersion\":\"20250325\"}; channel=distribution; deviceId=4fa268a041522085395d49d82a531ce0; idfa=; idfv=F0E5725C-09AE-4405-944F-B5EE88A6CFB3; machineid=iPhone15.2; os=iPhone OS; osver=16.2; packageType=release; sDeviceId=4fa268a041522085395d49d82a531ce0; JSESSIONID-WYYY=ebquFXgp%2FTulHhQm8fW2NUcvWHs9Wcp5vbW2rmNDuatSbNFmMmIeM9HsQtdxBxFEZdaOPhgpkPy5Wz5mSquj7C38kIBHKHI3EKV%5CjUaGj8DHBx7de32sNORBebz283%5CcsIPc4kzebG3rB%2FBZO0%2FRvw%5CVYrcq3QH2QO2C5cQkVDGcFC9u%3A1785345324774; *iuqxldmzr*=33; NMTID=00O9bi-ewpY8yFlr0CjkmO6TiDR6AAAAAGfrmrb6A; _ntes_nnid=aa571ef400169d56e07ca0db2f618790,1785336267791; _ntes_nuid=aa571ef400169d56e07ca0db2f618790; __csrf=8d67b6f0481f86cde9fddf43708b79d3; MUSIC_U=008268BF8011134007A2C412E6DFEA1722F6A63B72D2D57DA4508F1AEBE1307B16AE83DA81B8229C6539B7CD87EDFFF0A3DABF23FE0C83D86C87D98958563E6D5A01FC4CC60497539592D3BBD95F135A8F5026F22E05A05421E4465829F00FBD80F5914E90267FE4110D6AB534B79039F9A1215C0A0534F0330F8C32577CD8815D530317B2FE8ACAD5C76DF2B087438596121AC7BC6255424185FEEBBFDC24AD091AA4CF19B715CF229E4FFFECA63F59A0AB22220A885B46F9929D2FEAB7A3D18F2E3331332133DA08F5CB196617DDF6B08A1B8F66D758204E1D23A190A359F7BB9DBE25713F885D17D0F3C958A82870B5857E530F84ECF3FF597BE31A54B9018EBD668010706C65CAF5A3C19E9804180EE4C812EB34D4D6B90F5BCB6C7DDA1B5753260DAC3528FEF4A9F1F3C0B67F2E15294AAA5696151342268F1F9794AB603186C48F2804AEC4A1419F9D4E27794B7A323F05D9F33BB3C18B229A6F2609B931";

/** 返回 URL 的请求专用 User-Agent（模拟 NETEASE_USER_AGENT，硬编码） */
const NETEASE_USER_AGENT = "NeteaseMusic 9.5.60/7150 (iPhone; iOS 16.2; zh_CN)";

/** 返回 URL 的请求专用 MConfig-Info（模拟 NETEASE_MCONFIG_INFO，硬编码） */
const NETEASE_MCONFIG_INFO =
  '{"IuRPVVmc3WWul9fT":{"version":113289216,"appver":"9.5.60"},"zr4bw6pKFDIZScpo":{"version":3807232,"appver":"9.5.60"},"tPJJnts2H31BZXmp":{"version":5017600,"appver":"2.0.30"}}';

/** 与 NETEASE_COOKIE 一致的 iOS 设备指纹，用于 body 内的 eapi header（对齐 MeloX） */
const IOS_HEADER_DEFAULTS: Readonly<Record<string, string>> = {
  os: "iPhone OS",
  osver: "16.2",
  appver: "9.0.90",
  channel: "distribution",
};

/** 生成 WNMCID（进程级常量）：6 位小写字母.时间戳.01.0 */
const WNMCID = (() => {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  let s = "";
  for (let i = 0; i < 6; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
  return `${s}.${Date.now()}.01.0`;
})();

/** 每次请求生成：timestamp_XXXX 的递增式 id */
const generateRequestId = (): string => {
  const rand = Math.floor(Math.random() * 1000)
    .toString()
    .padStart(4, "0");
  return `${Date.now()}_${rand}`;
};

/** 补齐 cookie：注入 _ntes_nuid/_ntes_nnid/WNMCID/deviceId/appver 等客户端必备字段 */
const processCookieObject = (
  cookie: Record<string, string>,
  uri: string,
): Record<string, string> => {
  const ntesNuid = cookie._ntes_nuid || randomBytes(16).toString("hex");
  const os = OS_MAP[(cookie.os as keyof typeof OS_MAP) || "pc"] || OS_MAP.pc;

  const processed: Record<string, string> = {
    ...cookie,
    __remember_me: "true",
    ntes_kaola_ad: "1",
    _ntes_nuid: cookie._ntes_nuid || ntesNuid,
    _ntes_nnid: cookie._ntes_nnid || `${ntesNuid},${Date.now()}`,
    WNMCID: cookie.WNMCID || WNMCID,
    WEVNSM: cookie.WEVNSM || "1.0.0",
    osver: cookie.osver || os.osver,
    deviceId: cookie.deviceId || getDeviceId(),
    os: cookie.os || os.os,
    channel: cookie.channel || os.channel,
    appver: cookie.appver || os.appver,
  };

  // 登录类接口不带 NMTID（服务端要求）
  if (uri.indexOf("login") === -1) {
    processed.NMTID = randomBytes(8).toString("hex");
  }

  if (!processed.MUSIC_U) {
    processed.MUSIC_A = processed.MUSIC_A || getAnonymousToken();
    if (!processed.MUSIC_A) delete processed.MUSIC_A;
  }

  return processed;
};

/** 根据加密方式 + 设备类型选择 User-Agent */
const chooseUserAgent = (
  crypto: keyof typeof UA_MAP,
  uaType: "pc" | "android" | "iphone" | "linux" = "pc",
): string => {
  const map = UA_MAP[crypto] as Record<string, string> | undefined;
  return (map && map[uaType]) || "";
};

/**
 * 构造并发送请求
 * @param uri   接口路径，例如 `/api/w/login`；weapi 会自动替换前缀为 `/weapi/`
 * @param data  业务参数（不含 cookie/csrf，请求层会自动注入）
 * @param options 加密方式 / cookie / 代理等
 */
export const createRequest = async (
  uri: string,
  data: Record<string, unknown>,
  options: RequestOptions,
): Promise<RequestResponse> => {
  const headers: Record<string, string> = {};
  const ip = options.realIP || options.ip || "";
  if (ip) {
    headers["X-Real-IP"] = ip;
    headers["X-Forwarded-For"] = ip;
  }

  // 归一化 cookie 到对象并做一次补全
  let cookie: Record<string, string> =
    typeof options.cookie === "string" ? cookieToJson(options.cookie) : options.cookie || {};
  cookie = processCookieObject(cookie, uri);
  headers["Cookie"] = cookieObjToString(cookie);

  let crypto: CryptoMode | "" = options.crypto ?? "";
  if (crypto === "") crypto = "eapi";

  const csrfToken = csrfFrom(cookie);
  const useER = toBoolean(
    options.e_r !== undefined ? options.e_r : data.e_r !== undefined ? data.e_r : ENCRYPT_RESPONSE,
  );
  data.e_r = useER;

  let url = "";
  let encryptData: Record<string, string | number | boolean> | typeof data;

  switch (crypto) {
    case "weapi": {
      headers["Referer"] = options.domain || DOMAIN;
      headers["User-Agent"] = options.ua || chooseUserAgent("weapi");
      data.csrf_token = csrfToken;
      encryptData = encrypt.weapi(data);
      url = (options.domain || DOMAIN) + "/weapi/" + uri.slice(5);
      break;
    }
    case "linuxapi": {
      headers["User-Agent"] = options.ua || chooseUserAgent("linuxapi", "linux");
      encryptData = encrypt.linuxapi({
        method: "POST",
        url: (options.domain || DOMAIN) + uri,
        params: data,
      });
      url = (options.domain || DOMAIN) + "/api/linux/forward";
      break;
    }
    case "xeapi": {
      const publicKeyState = await ensureXeapiKey(cookie.deviceId);
      const xeapiOs = cookie.os === "android" ? cookie.os : "android";
      const xeapiAppver = cookie.os === "android" && cookie.appver ? cookie.appver : "9.1.65";
      const xeapiOsver = cookie.os === "android" && cookie.osver ? cookie.osver : "16";
      const xeapiBuildver = cookie.buildver || Date.now().toString().slice(0, 10);
      headers["User-Agent"] = options.ua || chooseUserAgent("api", "android");
      headers["X-Client-Enc-State"] = "ENCRYPTED";
      headers["x-aeapi"] = "true";
      headers["x-deviceid"] = cookie.deviceId;
      headers["x-os"] = xeapiOs;
      headers["x-osver"] = xeapiOsver;
      headers["x-appver"] = xeapiAppver;
      headers["x-sdeviceid"] = cookie.sDeviceId || cookie.deviceId;
      headers["x-buildver"] = xeapiBuildver;
      if (cookie.MUSIC_U) headers["x-music-u"] = cookie.MUSIC_U;
      headers["Cookie"] = cookieObjToString({
        ...cookie,
        os: xeapiOs,
        osver: xeapiOsver,
        appver: xeapiAppver,
        buildver: xeapiBuildver,
        sDeviceId: cookie.sDeviceId || cookie.deviceId,
      });
      const session = getXeapiSession();
      url = (options.domain || XEAPI_DOMAIN) + "/xeapi/" + uri.slice(5);
      encryptData = encrypt.xeapi(uri, data, {
        publicKeyState,
        sessionId: session.sessionId,
        sessionKey: session.sessionKey,
        os: xeapiOs,
      });
      break;
    }
    case "eapi":
    case "api": {
      // 返回 URL 的请求：body header 指纹用 iOS 值（对齐 MeloX），与 NETEASE_COOKIE 的 iPhone 身份一致
      const isUrlRequest = uri.includes(URL_PATH_KEYWORD);
      const header: Record<string, string> = {
        osver: isUrlRequest ? IOS_HEADER_DEFAULTS.osver : cookie.osver,
        deviceId: cookie.deviceId,
        os: isUrlRequest ? IOS_HEADER_DEFAULTS.os : cookie.os,
        appver: isUrlRequest ? IOS_HEADER_DEFAULTS.appver : cookie.appver,
        versioncode: cookie.versioncode || "140",
        mobilename: cookie.mobilename || "",
        buildver: cookie.buildver || Date.now().toString().slice(0, 10),
        resolution: cookie.resolution || "1920x1080",
        __csrf: csrfToken,
        channel: isUrlRequest ? IOS_HEADER_DEFAULTS.channel : cookie.channel,
        requestId: generateRequestId(),
      };
      if (cookie.MUSIC_U) header.MUSIC_U = cookie.MUSIC_U;
      if (cookie.MUSIC_A) header.MUSIC_A = cookie.MUSIC_A;
      headers["Cookie"] = cookieObjToString(header);
      headers["User-Agent"] =
        options.ua || (cookie.os === "osx" ? OSX_USER_AGENT : chooseUserAgent("api", "iphone"));

      if (crypto === "eapi") {
        (data as Record<string, unknown>).header = header;
        encryptData = encrypt.eapi(uri, data);
        url = (options.domain || API_DOMAIN) + "/eapi/" + uri.slice(5);
      } else {
        url = (options.domain || API_DOMAIN) + uri;
        encryptData = data;
      }
      break;
    }
    default:
      throw new Error(`Unknown crypto: ${crypto}`);
  }

  // 与 unblockneteasemusic 一致：路径含 "url" 的请求替换为硬编码的 cookie / UA / MConfig-Info
  if (uri.includes(URL_PATH_KEYWORD)) {
    if (NETEASE_COOKIE) headers["Cookie"] = NETEASE_COOKIE;
    if (NETEASE_USER_AGENT) headers["User-Agent"] = NETEASE_USER_AGENT;
    if (NETEASE_MCONFIG_INFO) headers["MConfig-Info"] = NETEASE_MCONFIG_INFO;
  }

  const body = new URLSearchParams(encryptData as Record<string, string>).toString();
  headers["Content-Type"] = "application/x-www-form-urlencoded";

  const answer: RequestResponse = { status: 500, body: {}, cookie: [] };
  const isXeapi = crypto === "xeapi";
  const needDecrypt = isXeapi || ((crypto === "eapi" || crypto === "weapi") && useER);

  let res: Response;
  try {
    res = await fetchWithProxy(url, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(8000),
    });
  } catch (err) {
    answer.status = 502;
    answer.body = { code: 502, msg: err instanceof Error ? err.message : String(err) };
    throw new NeteaseRequestError(answer);
  }

  // 收集 set-cookie
  const setCookie =
    (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ??
    (res.headers.get("set-cookie") ? [res.headers.get("set-cookie") as string] : []);
  answer.cookie = setCookie.map((x) => x.replace(/\s*Domain=[^(;|$)]+;*/, ""));

  // xeapi 会话密钥由响应头下发，缓存供后续请求复用
  if (isXeapi) {
    const ssid = res.headers.get("x-encr-ssid");
    const sskey = res.headers.get("x-encr-sskey");
    if (ssid && sskey) updateXeapiSession(ssid, sskey);
  }

  let parsed: NeteaseBody;
  try {
    if (needDecrypt) {
      const buf = Buffer.from(await res.arrayBuffer());
      parsed = (
        isXeapi
          ? encrypt.xeapiResDecrypt(buf)
          : encrypt.eapiResDecrypt(buf.toString("hex").toUpperCase(), headers["x-aeapi"] === "true")
      ) as NeteaseBody;
    } else {
      const text = await res.text();
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { code: res.status, raw: text };
      }
    }
    answer.body = parsed;
    if (parsed?.code !== undefined) parsed.code = Number(parsed.code);
    answer.status = Number(parsed?.code || res.status);
    if (typeof parsed?.code === "number" && SPECIAL_STATUS_CODES.has(parsed.code)) {
      answer.status = 200;
    }
  } catch {
    answer.body = { code: res.status, msg: "parse failed" };
    answer.status = res.status;
  }

  answer.status = answer.status > 100 && answer.status < 600 ? answer.status : 400;

  if (answer.status === 200) return answer;
  throw new NeteaseRequestError(answer);
};

/** 宽松的 boolean 解析 */
const toBoolean = (val: unknown): boolean => {
  if (typeof val === "boolean") return val;
  if (val === "") return false;
  return val === "true" || val === "1" || val === 1;
};
