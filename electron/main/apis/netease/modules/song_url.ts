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

import { requestMeloXIosPlayerURL } from "../core/ios_player_url";
import type { NeteaseModule } from "../core/types";

const song_url: NeteaseModule = async (query) => {
  const ids = query.id ?? query.ids;
  const data = {
    ids: `[${String(ids).split(",").join(",")}]`,
    level: query.level ?? "exhigh",
    encodeType: "flac",
  };

  // player/url/v1 固定使用 MeloX iOS EAPI 请求，完全绕过通用请求层。
  return requestMeloXIosPlayerURL(
    "/api/song/enhance/player/url/v1",
    data,
    query.cookie,
  );
};

export default song_url;
