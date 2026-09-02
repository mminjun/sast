"""게시글 통계 리포트."""

REPORT_PATH = "report.txt"


def write_report(rows):
    handle = open(REPORT_PATH, "a")
    for row in rows:
        handle.write(f"{row}\n")
    return REPORT_PATH


def load_last_report():
    try:
        with open(REPORT_PATH, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        pass
    return ""
