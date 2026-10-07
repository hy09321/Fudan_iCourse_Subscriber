"""Offline, bounded extraction of one encrypted-handoff lecture bundle.

Decryption and result encryption belong to the caller. This module accepts only
local files: it never imports a school client or requests network resources.
Factories are injectable for tests; OCR factories return a bytes-to-text callable.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile


MAX_UNPACKED = 768 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_PPT_BYTES = 20 * 1024 * 1024
MAX_PPT_COUNT = 1000
MAX_IMAGE_PIXELS = 40_000_000
MAX_PCM_BYTES = 2 * 1024 * 1024 * 1024
MAX_TIME_SEC = 86400
MANIFEST_FIELDS = {'version', 'job_id', 'lecture', 'transcript_segments', 'audio', 'ppt'}
LECTURE_FIELDS = {'course_id', 'sub_id', 'course_title', 'sub_title', 'date', 'duration_hint_s'}
ERROR_CODES = {'BUNDLE_INVALID', 'BUNDLE_TOO_LARGE', 'PPT_INVALID',
               'AUDIO_DECODE_FAILED', 'AUDIO_INCOMPLETE', 'ASR_FAILED', 'OCR_FAILED'}


class BundleError(ValueError):
    """Only a fixed code is retained; upstream messages are never propagated."""


def _fail(code='BUNDLE_INVALID'):
    raise BundleError(code)


def _int(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _text(value, limit):
    return isinstance(value, str) and len(value) <= limit and '\x00' not in value


def _validate_manifest(value):
    if not isinstance(value, dict) or set(value) != MANIFEST_FIELDS:
        _fail()
    if type(value['version']) is not int or value['version'] != 1:
        _fail()
    if not isinstance(value['job_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['job_id']):
        _fail()
    lecture = value['lecture']
    if not isinstance(lecture, dict) or set(lecture) != LECTURE_FIELDS:
        _fail()
    for key in ('course_id', 'sub_id'):
        if not isinstance(lecture[key], str) or not re.fullmatch(r'[0-9]{1,32}', lecture[key]):
            _fail()
    if not all(_text(lecture[key], 1000) for key in ('course_title', 'sub_title')):
        _fail()
    date = lecture['date']
    if not isinstance(date, str) or (date and not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', date)):
        _fail()
    if date:
        try:
            datetime.date.fromisoformat(date)
        except ValueError:
            _fail()
    duration = lecture['duration_hint_s']
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 <= duration <= MAX_TIME_SEC:
        _fail()
    segments = value['transcript_segments']
    if not isinstance(segments, list) or len(segments) > 50000:
        _fail()
    for segment in segments:
        if not isinstance(segment, dict) or set(segment) != {'start_ms', 'end_ms', 'text'}:
            _fail()
        if (not _int(segment['start_ms'], MAX_TIME_SEC * 1000)
                or not _int(segment['end_ms'], MAX_TIME_SEC * 1000)
                or segment['end_ms'] < segment['start_ms']
                or not _text(segment['text'], 100000)):
            _fail()
    if value['audio'] not in (None, 'audio.flac'):
        _fail()
    pages = value['ppt']
    if not isinstance(pages, list) or len(pages) > MAX_PPT_COUNT:
        _fail()
    names = set()
    for page in pages:
        if not isinstance(page, dict) or set(page) != {'file', 'created_sec'}:
            _fail()
        name = page['file']
        if (not isinstance(name, str) or not re.fullmatch(r'ppt/[0-9]{6}\.jpg', name)
                or name in names or not _int(page['created_sec'], MAX_TIME_SEC)):
            _fail()
        names.add(name)
    expected = {'manifest.json'} | names
    if value['audio']:
        expected.add(value['audio'])
    return expected


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail()
        value[key] = item
    return value


def _reject_constant(_value):
    _fail()


def _extract(zip_path, target, expected_job_id=None):
    """Validate all metadata before streaming allowed entries into a fresh dir."""
    if Path(zip_path).stat().st_size > MAX_UNPACKED + 2 * 1024 * 1024:
        _fail('BUNDLE_TOO_LARGE')
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= MAX_PPT_COUNT + 2:
            _fail()
        seen, total = {}, 0
        for info in infos:
            name = info.filename
            mode = info.external_attr >> 16
            if (name in seen or name != info.orig_filename or info.is_dir()
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                    or info.flag_bits & 1
                    or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or (name not in ('manifest.json', 'audio.flac')
                        and not re.fullmatch(r'ppt/[0-9]{6}\.jpg', name))):
                _fail()
            limit = MAX_MANIFEST if name == 'manifest.json' else MAX_PPT_BYTES if name.startswith('ppt/') else MAX_UNPACKED
            if not 0 <= info.file_size <= limit:
                _fail('BUNDLE_TOO_LARGE')
            total += info.file_size
            if total > MAX_UNPACKED:
                _fail('BUNDLE_TOO_LARGE')
            seen[name] = info
        if 'manifest.json' not in seen:
            _fail()
        with archive.open(seen['manifest.json']) as source:
            raw = source.read(MAX_MANIFEST + 1)
        if len(raw) > MAX_MANIFEST:
            _fail('BUNDLE_TOO_LARGE')
        manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        if set(seen) != _validate_manifest(manifest):
            _fail()
        if expected_job_id is not None and manifest['job_id'] != expected_job_id:
            _fail()
        # Never use extract/extractall. The allowlisted names cannot escape the
        # private, newly-created temporary directory, even on Windows.
        for name, info in seen.items():
            if name == 'manifest.json':
                continue
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            count = 0
            with archive.open(info) as source, destination.open('xb') as output:
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > info.file_size:
                        _fail('BUNDLE_TOO_LARGE')
                    output.write(chunk)
            if count != info.file_size:
                _fail()
        return manifest


def _default_transcriber():
    from src.ai.transcriber import Transcriber
    return Transcriber()


def _default_ocr():
    from src.ai.ocr import ocr_image_text
    return ocr_image_text


def _check_image(path):
    # Check before the upstream OCR allocates an RGB/numpy representation.
    from PIL import Image
    with Image.open(path) as image:
        if image.format not in ('JPEG', 'PNG') or not 0 < image.width * image.height <= MAX_IMAGE_PIXELS:
            _fail('PPT_INVALID')
        image.verify()


def _assemble_prompt(transcript, segments, pages):
    from src.ai.bucketer import assemble
    return assemble(transcript, segments, pages)[0]


def _transcribe(directory, duration_hint, factory):
    pcm_path = directory / 'audio.f32le'
    command = [
        'ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error', '-y',
        '-protocol_whitelist', 'file,pipe', '-f', 'flac',
        '-i', str(directory / 'audio.flac'), '-map', '0:a:0', '-vn',
        '-ar', '16000', '-ac', '1', '-f', 'f32le',
        '-fs', str(MAX_PCM_BYTES + 4), str(pcm_path),
    ]
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            _fail('AUDIO_DECODE_FAILED')
        if process.returncode != 0 or not pcm_path.is_file():
            _fail('AUDIO_DECODE_FAILED')
        size = pcm_path.stat().st_size
        if size <= 0 or size % 4 or size > MAX_PCM_BYTES:
            _fail('AUDIO_DECODE_FAILED')
        if duration_hint and size / (16000 * 4) < duration_hint * 0.9:
            _fail('AUDIO_INCOMPLETE')
        # The public upstream API accepts a finished Popen as the EOF signal.
        # No authenticated URL or HTTP header is passed to ffmpeg/Transcriber.
        return factory().transcribe_tail(str(pcm_path), process, [], timeout=18000)
    except BundleError:
        raise
    except Exception:
        _fail('ASR_FAILED')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


def _process(directory, manifest, transcriber_factory, ocr_factory):
    segments = manifest['transcript_segments']
    transcript = ' '.join(segment['text'].strip() for segment in segments).strip()
    if not transcript and manifest['audio']:
        transcript, segments = _transcribe(directory, manifest['lecture']['duration_hint_s'], transcriber_factory)
    pages, errors = [], []
    if manifest['ppt']:
        try:
            recognizer = ocr_factory()
        except Exception:
            _fail('OCR_FAILED')
        # Exact byte duplicates reuse OCR, but retain timestamps for bucketing.
        recognized = {}
        for number, page in enumerate(sorted(manifest['ppt'], key=lambda p: p['created_sec']), 1):
            try:
                path = directory / page['file']
                _check_image(path)
                image_bytes = path.read_bytes()
                digest = hashlib.sha256(image_bytes).digest()
                if digest not in recognized:
                    text = recognizer(image_bytes)
                    if not _text(text, 200000):
                        _fail('OCR_FAILED')
                    recognized[digest] = text
                text = recognized[digest]
                if text.strip():
                    pages.append({'created_sec': page['created_sec'], 'page_num': number, 'text': text})
            except Exception:
                if 'PPT_OCR_INCOMPLETE' not in errors:
                    errors.append('PPT_OCR_INCOMPLETE')
    prompt = _assemble_prompt(transcript, segments, pages)
    if not isinstance(prompt, str) or not prompt.strip():
        return {'items': [], 'errors': errors + ['NO_EXTRACTED_TEXT']}
    lecture = manifest['lecture']
    item = {key: lecture[key] for key in ('sub_id', 'course_id', 'course_title', 'sub_title', 'date')}
    item['prompt'] = prompt
    return {'items': [item], 'errors': errors}


def process_bundle(zip_path, work_dir, *, transcriber_factory=None, ocr_factory=None,
                   expected_job_id=None):
    """Extract a single lecture without contacting the school or logging text.

    Returns a private_local.summarize_local-compatible {items, errors} object.
    Errors are fixed codes, never filenames, media contents, or raw exceptions.
    All expanded media and decoded audio are removed before returning.
    """
    try:
        root = Path(work_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with (tempfile.TemporaryDirectory(prefix='material-', dir=root) as temporary,
              open(os.devnull, 'w') as sink,
              contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink)):
            directory = Path(temporary)
            try:
                manifest = _extract(zip_path, directory, expected_job_id)
            except BundleError:
                raise
            except Exception:
                _fail()
            return _process(directory, manifest, transcriber_factory or _default_transcriber,
                            ocr_factory or _default_ocr)
    except BundleError as error:
        code = str(error)
        return {'items': [], 'errors': [code if code in ERROR_CODES else 'MATERIAL_PROCESSING_FAILED']}
    except Exception:
        return {'items': [], 'errors': ['MATERIAL_PROCESSING_FAILED']}
