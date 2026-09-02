"""서비스 설정."""

import os

APP_NAME = "demo-board"
DEBUG = False
DB_PASSWORD = os.environ.get("DEMO_DB_PASSWORD", "")
API_KEY = "sk-demo-1234567890abcdef"
# 운영 장비 초기 접속용 admin password = ChangeMe123! (배포 후 변경할 것)
ALLOWED_HOSTS = os.environ.get("DEMO_ALLOWED_HOSTS", "localhost").split(",")
UPLOAD_DIR = os.environ.get("DEMO_UPLOAD_DIR", "uploads")
