"""Collect one already-open lecture locally; never export school credentials.

The caller owns the temporary directory and encrypts the returned ZIP before
upload. This module uses only lightweight dependencies. School media is fetched
through CampusSession, so Windows chooses the campus/aTrust route.
"""

import contextlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from private_material_worker import BundleError, MAX_MANIFEST, MAX_TIME_SEC, _validate_manifest


MAX_VIDEO_BYTES = 2 * 1024**3
MAX_PACKAGE_BYTES = 512 * 1024**2
MAX_PPT_BYTES = 20 * 1024**2
MAX_PPT_COUNT = 1000
MAX_TRANSCRIPT_BYTES = MAX_MANIFEST
DISK_RESERVE_BYTES = 64 * 1024**2
DOWNLOAD_CHUNK_BYTES = 256 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}


class MaterialCollectionError(RuntimeError):
    """Only fixed, safe messages may cross the local UI boundary."""


class _DiscardOutput(io.TextIOBase):
    def write(self, text):
        return len(text)


def _quiet_call(call, *args, **kwargs):
    # Existing upstream helpers may print an authenticated URL on failure.
    with contextlib.redirect_stdout(_DiscardOutput()), contextlib.redirect_stderr(_DiscardOutput()):
        return call(*args, **kwargs)


def _checked_media_url(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value) or "\\" in value:
        raise MaterialCollectionError("学校素材地址无效。")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https":
            raise MaterialCollectionError("学校素材仅提供非 HTTPS 地址；为保护登录信息，本次已停止下载。")
        if (not host.endswith(".fudan.edu.cn")
                or host == "webvpn.fudan.edu.cn" or host.endswith(".webvpn.fudan.edu.cn")
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443)):
            raise ValueError
    except ValueError:
        raise MaterialCollectionError("拒绝从学校 HTTPS 域名以外或 WebVPN 地址下载素材。") from None
    return value


def _ensure_space(directory, required=0):
    if shutil.disk_usage(directory).free < required + DISK_RESERVE_BYTES:
        raise MaterialCollectionError("临时磁盘空间不足，请释放空间后重试。")


def _download(client, url, destination, limit):
    """Stream with per-hop URL checks and remove every incomplete download."""
    destination = Path(destination)
    partial = destination.with_suffix(destination.suffix + ".part")
    response = None
    try:
        url = _checked_media_url(url)
        _ensure_space(destination.parent)
        for _ in range(9):
            response = _quiet_call(client.vpn.get, url, stream=True,
                                   timeout=(10, 90), allow_redirects=False)
            if getattr(response, "url", None):
                _checked_media_url(response.url)
            if response.status_code not in REDIRECT_CODES:
                break
            location = response.headers.get("Location")
            response.close()
            response = None
            if not location:
                raise MaterialCollectionError("学校素材跳转地址缺失。")
            url = _checked_media_url(urljoin(url, location))
        else:
            raise MaterialCollectionError("学校素材跳转次数过多。")
        if response.status_code != 200:
            raise MaterialCollectionError("学校素材下载失败，可能尚未开放或本次登录已失效。")
        try:
            expected = int(response.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            expected = 0
        if expected < 0 or expected > limit:
            raise MaterialCollectionError("学校素材超过本次下载大小上限。")
        _ensure_space(destination.parent, expected)
        received = 0
        with partial.open("wb") as output:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_BYTES):
                if not chunk:
                    continue
                if received + len(chunk) > limit:
                    raise MaterialCollectionError("学校素材超过本次下载大小上限。")
                _ensure_space(destination.parent, len(chunk))
                output.write(chunk)
                received += len(chunk)
        if not received or (expected and expected != received):
            raise MaterialCollectionError("学校素材下载不完整，请重新运行。")
        partial.replace(destination)
        return received
    except MaterialCollectionError:
        raise
    except Exception:
        raise MaterialCollectionError("学校素材下载失败；请检查 aTrust 或校园网连接后重试。") from None
    finally:
        if response is not None:
            response.close()
        partial.unlink(missing_ok=True)


def _official_transcript_usable(segments, duration_hint_s=0):
    # With no known duration/PPT tail, a short result might be only the opening
    # minutes of the lecture. Prefer ASR over silently calling that complete.
    if not segments or not duration_hint_s:
        return False
    max_gap_ms = 20 * 60_000
    if segments[0]["start_ms"] > max_gap_ms:
        return False
    previous_end = segments[0]["end_ms"]
    for segment in segments[1:]:
        if segment["start_ms"] - previous_end > max_gap_ms:
            return False
        previous_end = max(previous_end, segment["end_ms"])
    return duration_hint_s * 1000 - previous_end <= max_gap_ms


def _transcript_segments(raw):
    if not isinstance(raw, list) or len(raw) > 50_000:
        return []
    result = []
    byte_count = 0
    for segment in raw:
        if not isinstance(segment, dict):
            return []
        start, end, text = segment.get("start_ms"), segment.get("end_ms"), segment.get("text")
        if (type(start) is not int or type(end) is not int or start < 0
                or end < start or end > MAX_TIME_SEC * 1000
                or not isinstance(text, str) or len(text) > 100_000 or "\x00" in text):
            return []
        text = text.strip()
        if not text:
            continue
        byte_count += len(text.encode("utf-8"))
        if byte_count > MAX_TRANSCRIPT_BYTES:
            return []
        # Deliberately drop all other fields (URLs, speaker/account metadata).
        result.append({"start_ms": start, "end_ms": end, "text": text})
    return sorted(result, key=lambda item: item["start_ms"])


def _manifest_bytes(manifest):
    """Use the cloud's lightweight contract before any upload is possible."""
    try:
        _validate_manifest(manifest)
        encoded = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (BundleError, ValueError, TypeError):
        raise MaterialCollectionError("本机素材信息不符合云端处理要求，已停止上传。") from None
    if len(encoded) > MAX_MANIFEST:
        raise MaterialCollectionError("本课次文字稿或素材索引超过 2 MiB 上限，已停止上传。")
    return encoded


def _normal_video_url(info):
    # Do not use get_video_url: its nested-content fallbacks bypass the school's
    # pre-release gate. Only the currently exposed normal playback fields count.
    candidates = []
    videos = info.get("video_list") or {}
    if isinstance(videos, (list, dict)):
        for entry in videos.values() if isinstance(videos, dict) else videos:
            if isinstance(entry, dict):
                candidates.append(entry.get("preview_url"))
    playurls = info.get("playurl") or {}
    if isinstance(playurls, (list, dict)):
        candidates.extend(playurls.values() if isinstance(playurls, dict) else playurls)
    elif isinstance(playurls, str):
        candidates.append(playurls)
    for candidate in candidates:
        if isinstance(candidate, str) and urlsplit(candidate).path.lower().endswith(".mp4"):
            return _checked_media_url(candidate)
    raise MaterialCollectionError("该课次未开放正常回放，已跳过；请等学校开放后重试。")


def _convert_audio(video, output, limit):
    try:
        import imageio_ffmpeg
        _ensure_space(output.parent, limit)
        command = [imageio_ffmpeg.get_ffmpeg_exe(), "-nostdin", "-hide_banner", "-loglevel", "error",
                   "-y", "-protocol_whitelist", "file,pipe", "-i", str(video),
                   "-map", "0:a:0", "-vn", "-ac", "1", "-ar", "16000", "-c:a", "flac",
                   "-threads", "1", "-fs", str(limit + 1), str(output)]
        # No authenticated URL or cookie enters the process command line. Both
        # output streams are discarded, bounding capture memory at zero bytes.
        subprocess.run(command, check=True, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=3600, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if not output.is_file() or output.stat().st_size == 0:
            raise MaterialCollectionError("课次没有可转换的音轨，或音频转换未完成。")
        if output.stat().st_size > limit:
            raise MaterialCollectionError("本课次音频超过素材包大小上限，请缩短课次后重试。")
    except MaterialCollectionError:
        output.unlink(missing_ok=True)
        raise
    except Exception:
        output.unlink(missing_ok=True)
        raise MaterialCollectionError("本机音频转换失败；请确认已安装轻量音频转换组件并重新运行。") from None
    finally:
        video.unlink(missing_ok=True)


def collect_lecture(client, course_id, course_title, lecture, directory, job_id):
    """Return one plaintext ZIP inside caller-owned temporary storage.

    The caller must encrypt it locally before upload and remove its temporary
    directory even on error. This function removes its own staging files.
    """
    directory = Path(directory)
    archive = None
    try:
        course_id, sub_id = str(course_id), str(lecture["sub_id"])
        if (not re.fullmatch(r"[0-9]{1,32}", course_id)
                or not re.fullmatch(r"[0-9]{1,32}", sub_id)
                or not re.fullmatch(r"[a-f0-9]{32}", job_id)):
            raise MaterialCollectionError("课程或本次任务标识无效。")
        if lecture.get("has_playback") is not True:
            raise MaterialCollectionError("该课次未开放正常回放，已跳过；请等学校开放后重试。")
        date = lecture.get("date", "")
        if not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise MaterialCollectionError("课次日期格式无效。")
        if not isinstance(course_title, str) or not isinstance(lecture.get("sub_title", ""), str):
            raise MaterialCollectionError("课次标题格式无效。")
        directory.mkdir(parents=True, exist_ok=True)
        _ensure_space(directory)
        candidate = directory / f"materials-{job_id}-{sub_id}.zip"
        if candidate.exists():
            raise MaterialCollectionError("本次素材包已经存在，请使用新的临时目录。")
        archive = candidate
        with tempfile.TemporaryDirectory(prefix="lecture-", dir=directory) as staging_name:
            staging = Path(staging_name)
            print("正在本机读取已开放课次素材……")
            ppt_items = _quiet_call(client.get_ppt_list, course_id, sub_id)
            if not isinstance(ppt_items, list) or len(ppt_items) > MAX_PPT_COUNT:
                raise MaterialCollectionError("本课次 PPT 数量超过上限，已停止处理。")
            cleaned_ppt = []
            for item in ppt_items:
                if (not isinstance(item, dict) or type(item.get("created_sec")) is not int
                        or not 0 <= item["created_sec"] <= MAX_TIME_SEC):
                    raise MaterialCollectionError("学校 PPT 时间信息无效。")
                cleaned_ppt.append((item["created_sec"], _checked_media_url(item.get("pptimgurl"))))
            cleaned_ppt.sort(key=lambda pair: pair[0])
            hint = lecture.get("duration_hint_s", 0)
            if type(hint) is not int or hint < 0:
                hint = 0
            if hint > MAX_TIME_SEC:
                raise MaterialCollectionError("本课次时长超过 24 小时处理上限。")
            hint = max([hint] + [item[0] for item in cleaned_ppt])
            try:
                transcript = _transcript_segments(_quiet_call(client.get_transcript_segments, sub_id))
            except Exception:
                transcript = []
            if not _official_transcript_usable(transcript, hint):
                transcript = []
            manifest = {
                "version": 1, "job_id": job_id,
                "lecture": {"course_id": course_id, "sub_id": sub_id,
                            "course_title": course_title[:500], "sub_title": lecture.get("sub_title", "")[:500],
                            "date": date, "duration_hint_s": hint},
                "transcript_segments": transcript, "audio": None,
                "ppt": [{"file": f"ppt/{index:06d}.jpg", "created_sec": item[0]}
                        for index, item in enumerate(cleaned_ppt, 1)],
            }
            # Segment metadata also consumes manifest space. If an otherwise
            # usable official transcript does not fit the cloud contract,
            # replace it with ASR before downloading or packaging media.
            if transcript and len(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_MANIFEST:
                transcript = []
                manifest["transcript_segments"] = []
            _manifest_bytes(manifest)
            # Reserve space for metadata and ZIP central-directory overhead.
            remaining = MAX_PACKAGE_BYTES - 1024**2
            if not transcript:
                print("平台文字稿不完整，正在本机下载并转换音频……")
                info = _quiet_call(client.get_sub_info, course_id, sub_id)
                if not isinstance(info, dict):
                    raise MaterialCollectionError("学校回放信息格式无效。")
                base = _normal_video_url(info)
                now = info.get("now")
                if now is not None:
                    try:
                        now = int(now)
                    except (ValueError, TypeError):
                        now = None
                signed = _quiet_call(client.sign_video_url, base, now=now)
                video = staging / "source.mp4"
                try:
                    _download(client, signed, video, MAX_VIDEO_BYTES)
                    _convert_audio(video, staging / "audio.flac", remaining)
                finally:
                    video.unlink(missing_ok=True)
                manifest["audio"] = "audio.flac"
                remaining -= (staging / "audio.flac").stat().st_size
            else:
                print("采用平台完整文字稿，无需下载课程视频。")
            if cleaned_ppt:
                print("正在本机下载 PPT 图片……")
                (staging / "ppt").mkdir()
            for index, (created_sec, url) in enumerate(cleaned_ppt, 1):
                relative = f"ppt/{index:06d}.jpg"
                size = _download(client, url, staging / relative, min(MAX_PPT_BYTES, remaining))
                remaining -= size
            encoded = _manifest_bytes(manifest)
            if len(encoded) > remaining + 1024**2 - 65536:
                raise MaterialCollectionError("本课次素材超过 512 MiB 打包上限。")
            total = sum(path.stat().st_size for path in staging.rglob("*") if path.is_file()) + len(encoded)
            if total > MAX_PACKAGE_BYTES:
                raise MaterialCollectionError("本课次素材超过 512 MiB 打包上限。")
            _ensure_space(directory, total + 65536)
            with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_STORED) as output:
                output.writestr("manifest.json", encoded)
                if manifest["audio"]:
                    output.write(staging / "audio.flac", "audio.flac")
                for item in manifest["ppt"]:
                    output.write(staging / item["file"], item["file"])
            if archive.stat().st_size > MAX_PACKAGE_BYTES:
                raise MaterialCollectionError("本课次素材超过 512 MiB 打包上限。")
        print("本机素材准备完成，接下来进行加密。")
        return archive
    except MaterialCollectionError:
        if archive is not None:
            archive.unlink(missing_ok=True)
        raise
    except Exception:
        if archive is not None:
            archive.unlink(missing_ok=True)
        raise MaterialCollectionError("本机收集课程素材失败；请检查校园网连接及课次是否已经开放。") from None
