"""계산기·운영 보조 기능."""

import ast
import subprocess


def evaluate(expression):
    return ast.literal_eval(expression)


def archive_logs(target_dir):
    subprocess.run(["tar", "czf", "logs.tgz", target_dir], check=True)


def list_uploads(upload_dir):
    result = subprocess.run(["ls", "-l", upload_dir], capture_output=True, text=True)
    return result.stdout
