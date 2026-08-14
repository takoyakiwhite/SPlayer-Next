import * as encrypt from "./crypto";
import { cookieToJson } from "./cookie";
import { fetchWithProxy } from "@main/utils/proxy";
import type { RequestResponse } from "./request";

const DOMAIN = "https://interface.music.163.com";
const IOS_USER_AGENT =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";

const serializeCookie = (cookie: Record<string, string>): string =>
  Object.entries(cookie)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ");

const parseCookie = (
  cookie: string | Record<string, string> | undefined,
): Record<string, string> =>
  typeof cookie === "string" ? cookieToJson(cookie) : { ...(cookie || {}) };

/**
 * MeloX iOS unauthenticated EAPI request path.
 *
 * This intentionally bypasses SPlayer's generic Netease request serializer so
 * player/download URL requests use the same client identity, cookie handling,
 * EAPI payload, UA and HTTP transport as MeloX.
 */
export const requestMeloXIosEapi = async (
  uri: string,
  data: Record<string, unknown>,
  cookieInput?: string | Record<string, string>,
): Promise<RequestResponse> => {
  const cookie = parseCookie(cookieInput);
  cookie.os = cookie.os || "ios";
  cookie.appver = cookie.appver || "9.0.90";
  cookie.__remember_me = "true";

  const csrf = cookie.__csrf || "";
  const header: Record<string, string> = {
    os: "ios",
    appver: "9.0.90",
    osver: "18.0",
    buildver: String(Math.floor(Date.now() / 1000)),
    channel: "distribution",
    requestId: `${Date.now()}_0000`,
    __csrf: csrf,
  };

  if (cookie.MUSIC_U) header.MUSIC_U = cookie.MUSIC_U;

  const requestData = {
    ...data,
    header,
    e_r: false,
  };
  const { params } = encrypt.eapi(uri, requestData);
  const body = new URLSearchParams({ params }).toString();

  let response: Response;
  try {
    response = await fetchWithProxy(
      `${DOMAIN}${uri.replace("/api/", "/eapi/")}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": IOS_USER_AGENT,
          Cookie: serializeCookie(cookie),
        },
        body,
        signal: AbortSignal.timeout(15000),
      },
    );
  } catch (error) {
    return {
      status: 502,
      body: {
        code: 502,
        msg: error instanceof Error ? error.message : String(error),
      },
      cookie: [],
    };
  }

  const setCookie =
    (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ??
    (response.headers.get("set-cookie") ? [response.headers.get("set-cookie") as string] : []);

  const text = await response.text();
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    parsed = { code: response.status, raw: text };
  }

  const code = Number(parsed.code ?? response.status);
  return {
    status: code > 100 && code < 600 ? code : response.status,
    body: parsed,
    cookie: setCookie.map((value) => value.replace(/\s*Domain=[^(;|$)]+;*/, "")),
  };
};

/** Backward-compatible name for the player URL call site. */
export const requestMeloXIosPlayerURL = requestMeloXIosEapi;
