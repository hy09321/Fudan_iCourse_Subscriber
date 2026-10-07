"""Manual cloud worker. Receives a temporary session, never a password/API key."""
import contextlib
import json
import os
import re
import sys
from pathlib import Path
from private_protocol import validate_job, encrypt_result


def process(job):
    from src.runtime import config
    from src.api.webvpn import WebVPNSession
    from src.api.icourse import ICourseClient
    from src.data.database import Database
    from src.runtime.reporter import Reporter
    from src.runtime.scheduler import Scheduler
    from src.ai.transcriber import Transcriber
    from src.pipeline.lecture_runner import LectureRunner
    from src.ai.bucketer import assemble

    # Do not invoke main.py: it logs in with a password and calls an LLM.
    config.STUDENT_ID = config.PASSWORD = ''
    config.USE_OFFICIAL_TRANSCRIPT = True
    vpn = WebVPNSession()
    for cookie in job['cookies']:
        vpn.session.cookies.set(**cookie)
    job['cookies'].clear()
    vpn.logged_in = True
    client = ICourseClient(vpn)
    if not client.check_alive():
        return {'items': [], 'errors': ['SESSION_REJECTED: log in locally again; cross-IP sessions may be unsupported.']}
    db = Database()
    reporter = Reporter()
    scheduler = Scheduler(reporter)
    items, errors = [], []

    class ExtractionRunner(LectureRunner):
        def _summarize(self, sub_id, course_title, transcript, transcript_segments):
            prompt, _ = assemble(transcript, transcript_segments, db.get_done_ppt_pages(sub_id))
            self.extracted = {'sub_id': sub_id, 'course_title': course_title, 'prompt': prompt}
            return 'extracted locally; summary is generated on the user computer'

    runner = ExtractionRunner(client, db, scheduler, Transcriber(), None, reporter)
    completed = set(job['skip_ids'])
    try:
        for course_id in job['course_ids']:
            if not client.check_alive():
                errors.append('SESSION_EXPIRED: log in locally again')
                break
            try:
                detail = client.get_course_detail(course_id)
            except Exception:
                errors.append(f'COURSE_UNAVAILABLE:{course_id}')
                continue
            title = detail['title']
            db.upsert_course(course_id, title, detail.get('teacher', ''))
            seen = set()
            for lecture in detail['lectures']:
                sub_id = str(lecture['sub_id'])
                date = lecture.get('date', '') or lecture.get('sub_title', '')[:10]
                if (not lecture.get('has_playback') or sub_id in completed
                        or sub_id in seen or (re.fullmatch(r'\d{4}-\d{2}-\d{2}', date) and date < job['since'])):
                    continue
                seen.add(sub_id)
                if not client.check_alive():
                    errors.append('SESSION_EXPIRED: log in locally again')
                    return {'items': items, 'errors': errors}
                db.insert_lecture(sub_id, course_id, lecture.get('sub_title', sub_id), date)
                runner.extracted = None
                try:
                    runner.run(course_id, title, lecture, next_info=None)
                    if runner.extracted:
                        items.append({**runner.extracted, 'course_id': course_id,
                                      'sub_title': lecture.get('sub_title', sub_id), 'date': date})
                    else:
                        errors.append(f'NO_TRANSCRIPT:{sub_id}')
                except Exception:
                    # Detailed upstream exception messages can contain authenticated URLs.
                    errors.append(f'EXTRACTION_FAILED:{sub_id}')
                finally:
                    scheduler.image_cache.discard(sub_id)
                    scheduler.audio_downloader.release(sub_id)
    finally:
        scheduler.shutdown()
        db.conn.close()
        vpn.session.close()
    return {'items': items, 'errors': errors}


def main():
    raw = os.environ.pop('ICS_SESSION_JOB', '')
    expected = os.environ.get('ICS_JOB_ID', '')
    test_mode = os.environ.get('ICS_TEST_MODE') == 'true'
    if test_mode:
        from Crypto.Random import get_random_bytes
        from private_protocol import decrypt_result
        key = get_random_bytes(32)
        sample = {'items': [{'prompt': 'privacy self-test'}], 'errors': []}
        assert decrypt_result(encrypt_result(sample, key, 'test'), key, 'test') == sample
        # Also import all heavy modules, without visiting the school or loading a model.
        from src.pipeline.lecture_runner import LectureRunner
        from src.ai.transcriber import Transcriber
        print('Offline protocol and cloud imports passed; no credentials used.')
        return 0
    try:
        job = json.loads(raw)
        del raw
        key = validate_job(job)
        if job['job_id'] != expected:
            raise ValueError('Job ID mismatch')
    except Exception:
        print('Invalid or expired session handoff. Run the local helper again.')
        return 2
    try:
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            result = process(job)
    except Exception:
        result = {'items': [], 'errors': ['CLOUD_PROCESSING_FAILED']}
    output = Path(os.environ['ICS_RESULT_DIR'])
    output.mkdir(parents=True, exist_ok=True)
    (output / 'result.enc').write_bytes(encrypt_result(result, key, expected))
    print('Encrypted result ready. No school password or model API key was provided.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
