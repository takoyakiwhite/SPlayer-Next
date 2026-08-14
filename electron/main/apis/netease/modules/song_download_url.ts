/**
 * 获取歌曲下载地址（v1，固定使用 MeloX iOS EAPI）
 */

import { requestMeloXIosEapi } from "../core/ios_player_url";
import type { NeteaseModule } from "../core/types";

const song_download_url: NeteaseModule = async (query) => {
  const data = {
    id: query.id,
    level: query.level ?? "exhigh",
  };

  // download/url/v1 与 player/url/v1 一样，固定复用 MeloX iOS EAPI 请求。
  return requestMeloXIosEapi(
    "/api/song/enhance/download/url/v1",
    data,
    query.cookie,
  );
};

export default song_download_url;
