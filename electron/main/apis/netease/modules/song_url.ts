/**
 * 获取歌曲播放地址（v1 端点，level 而非裸 br）
 *
 * params:
 * - id / ids   歌曲 id（单个或逗号分隔）
 * - level      音质 level，默认 exhigh（320k MP3）
 *              standard / exhigh / lossless / hires / jyeffect / sky / jymaster
 *
 * 响应：`{ code, data: [{ id, url, br, level, freeTrialInfo, ... }] }`
 * - url == null：VIP / 版权未开放
 * - freeTrialInfo != null：仅 30s 试听片段
 */

import { cookieToJson } from "../core/cookie";
import { createOption } from "../core/option";
import type { NeteaseModule } from "../core/types";

const IOS_USER_AGENT =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";

const song_url: NeteaseModule = (query, request) => {
  const ids = query.id ?? query.ids;
  const data = {
    ids: `[${String(ids).split(",").join(",")}]`,
    level: query.level ?? "exhigh",
    encodeType: "flac",
  };

  const cookie =
    typeof query.cookie === "string"
      ? cookieToJson(query.cookie)
      : { ...(query.cookie ?? {}) };

  // 与 MeloX iOS 播放请求保持一致：EAPI + iOS 18.0 UA/客户端身份。
  return request(
    "/api/song/enhance/player/url/v1",
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

export default song_url;
