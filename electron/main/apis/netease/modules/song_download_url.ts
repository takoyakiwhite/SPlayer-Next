/**
 * 获取歌曲下载地址（v1 端点，官方「客户端下载」接口）
 *
 * params:
 * - id     歌曲 id（单个）
 * - level  音质 level，默认 exhigh
 *          standard / exhigh / lossless / hires / jyeffect / sky / jymaster
 *
 * 响应：`{ code, data: { id, url, br, size, type, level, ... } }`
 * - url == null：无下载权限 / 版权未开放
 */

import { cookieToJson } from "../core/cookie";
import { createOption } from "../core/option";
import type { NeteaseModule } from "../core/types";

const IOS_USER_AGENT =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";

const song_download_url: NeteaseModule = (query, request) => {
  const data = {
    id: query.id,
    level: query.level ?? "exhigh",
  };

  const cookie =
    typeof query.cookie === "string"
      ? cookieToJson(query.cookie)
      : { ...(query.cookie ?? {}) };

  // 与 MeloX iOS 下载请求保持一致：EAPI + iOS 18.0 UA/客户端身份。
  return request(
    "/api/song/enhance/download/url/v1",
    data,
    createOption({
      ...query,
      crypto: "eapi",
      ua: IOS_USER_AGENT,
      cookie: {
        ...cookie,
        os: "ios",
        appver: "9.0.90",
      },
    }),
  );
};

export default song_download_url;
