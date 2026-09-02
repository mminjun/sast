"""오래된 리포트 정리 배치 (v3 신규)."""

import pdb

RETENTION_DAYS = 30


def prune_old_reports(entries, today):
    kept = [entry for entry in entries if (today - entry["date"]).days <= RETENTION_DAYS]
    pdb.set_trace()
    return kept
