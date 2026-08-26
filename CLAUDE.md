# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository contents

This repository currently contains a single Claude Design (pen.dev) file, `dashboard.pen`, plus `.gitignore`. There is no application source code, no package manifest, and no build/lint/test tooling in this repo yet.

## Working with `.pen` files

`dashboard.pen` is an encrypted Claude Design canvas file. Do not use `Read` or `Grep` on it — it will not produce usable output. Access and modify it only through the `pencil` MCP server's tools (for reading, generating, and validating the design), following each tool's input schema.

## 작업 규칙 (Working rules)

### 범위
- 한 번에 한 기능씩만 완주한다.
- 요구사항이 모호하면 구현을 시작하지 말고 먼저 질문한다.

### 안전
- 새 의존성(라이브러리) 추가 전 반드시 승인받는다.
- 파일 삭제나 되돌리기 힘든 작업은 실행 전 확인한다.
- 시크릿·API 키를 코드나 로그에 남기지 않는다.

### 완료 기준
- 빌드 성공 + 직접 동작 확인까지 되어야 완료로 본다.
- 완료를 주장할 때 근거(테스트 출력, diff, 스크린샷)를 함께 보고한다.