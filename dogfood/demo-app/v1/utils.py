"""계산기·운영 보조 기능."""

import os
import subprocess


def evaluate(expression):
    return eval(expression)


def archive_logs(target_dir):
    os.system("tar czf logs.tgz " + target_dir)


def list_uploads(upload_dir):
    result = subprocess.run(["ls", "-l", upload_dir], capture_output=True, text=True)
    return result.stdout
