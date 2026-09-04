"""CI 게이트 차단 시연용 — 이 파일은 병합하지 않는다.

신규 HIGH(KISA-IV-01 SQL 삽입)를 일부러 넣어 .github/workflows/sast-scan.yml이 PR을
차단하는 것을 보여준다 (docs/decisions.md 2026-09-04, README 스크린샷).
"""


def find_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
