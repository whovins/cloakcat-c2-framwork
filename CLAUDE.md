# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CloakCat is a Rust-based C2 (Command and Control) framework for red-team research. It uses a 3-tier architecture:
- **cat-server**: Axum HTTP API + PostgreSQL persistence
- **cat-agent**: Beacon that long-polls for commands and executes them
- **cat-cli** (`catctl`): Interactive operator REPL
- **cloakcat-protocol**: Shared types, crypto, and URL path helpers

## Commands

### Build

```bash
# Full workspace
cargo build --workspace

# Individual components
cargo build -p cat-server
cargo build -p cat-agent
cargo build -p catctl
cargo build -p cloakcat-protocol

# Release builds
cargo build --release -p cat-server
cargo build --release -p cat-agent

# Cross-compile agent for Windows (from Linux)
cargo build --target x86_64-pc-windows-gnu -p cat-agent --release
```

### Database

```bash
docker-compose up        # Start PostgreSQL dev instance (port 5432)
```

Migrations in `cat-server/migrations/` are applied automatically via `sqlx::migrate!` at server startup.

### Run

```bash
# Server (reads DATABASE_URL, SHARED_TOKEN, OPERATOR_TOKEN from .env)
cargo run -p cat-server

# CLI
cargo run -p catctl
```

## Architecture

### Data Flow

```
Agent → POST /register (X-Agent-Token header)
Agent → GET  /poll/{agent_id}?hold=45   (long-poll, 45-second hold)
Agent → POST /result/{agent_id}          (HMAC-SHA256 signed body)

Operator → POST /command/{agent_id}      (X-Operator-Token header)
Operator → GET  /admin/results           (fetch results)
```

### Authentication Layers

- **X-Agent-Token** (`SHARED_TOKEN`): Used by agent for registration and polling. Compared with `ring::constant_time::verify_slices_are_equal` to prevent timing attacks.
- **X-Operator-Token** (`OPERATOR_TOKEN`): Protected routes in `middleware.rs` via `auth_middleware`.
- **HMAC-SHA256 result integrity**: Message = `agent_id + cmd_id + stdout` (no separators). Verified in `cloakcat-protocol/src/crypto.rs`.

### Key Module Responsibilities

| Module | File | Role |
|--------|------|------|
| Server startup | `cat-server/src/main.rs` | Loads env, TLS config, binds listener (HTTP :3000 / HTTPS :3443) |
| Route wiring | `cat-server/src/routes.rs` | Public vs. operator-protected route splits |
| Handlers | `cat-server/src/handlers.rs` | All HTTP request handlers |
| DB queries | `cat-server/src/db.rs` | All SQLx queries (compile-time checked) |
| Validation | `cat-server/src/validation.rs` | Health profile path + User-Agent matching |
| Beacon loop | `cat-agent/src/beacon.rs` | Register → infinite poll/execute/upload with jitter + exponential backoff |
| Agent config | `cat-agent/src/config.rs` | Loads `AgentConfig` from embedded bytes (`CLOAKCAT_EMBED_CONFIG`) or file override |
| Shared types | `cloakcat-protocol/src/types.rs` | `RegisterReq`, `Command`, `ResultReq`, `AgentConfig` structs |
| URL paths | `cloakcat-protocol/src/paths.rs` | `Endpoints` struct generates register/poll/result URLs; supports health profile camouflage |

### Database Schema

PostgreSQL tables: `agents`, `commands`, `results`, `audit`. Key columns:
- `agents.tags`: JSONB column for arbitrary operator metadata
- `agents.kill_after_hours`: Auto-expiry for agents
- `audit`: Immutable log of operator actions (actor, action, target_type, target_id, context)

### Agent Config Embedding

Agent config is embedded at compile time via `build.rs` using the `CLOAKCAT_EMBED_CONFIG` env var pointing to a config file. This bakes `server_url`, `shared_token`, and timing params directly into the binary.

### TLS

Optional. Set `TLS_CERT_PATH` and `TLS_KEY_PATH` in `.env` to enable HTTPS. Without them, server logs a warning and runs HTTP only.

### Health Profile Camouflage

Agents can masquerade as health check traffic. `HEALTH_PROFILE_NAME`, `HEALTH_BASE_PATH`, and `HEALTH_USER_AGENT` constants in `cloakcat-protocol/src/constants.rs` control this. `validation.rs` enforces the pattern server-side.

## Cursor Rules (`.cursorrules`)

- Prefer Rust idioms; minimize external dependencies
- Use `sqlx` for all DB access (compile-time query checking)
- Security/OPSEC mindset: timing-safe comparisons, no secrets in logs
- Scope control: don't add features beyond the current milestone

## 개선 로드맵

### 유지해야 할 기존 설계 (변경 금지)
- 4-crate 워크스페이스 구조와 의존성 방향
- sqlx 컴파일 타임 쿼리 검증 패턴
- View 타입 (DB ↔ API 분리) 패턴
- build.rs 컨피그 임베딩 방식
- Exponential backoff + jitter 재시도 전략
- ring constant-time 비교 (middleware.rs)
- debug_log 매크로
- Agent ID 파일 지속성
- Axum 미들웨어 인증 구조

### 진행 상황
- [x] Phase 0: 즉시 수정 (F1~F5) — HMAC 타이밍/구분자, 타임아웃, 크기제한
- [x] Phase 1: 서버 리팩토링 (R1, R7, R4, R6) — service 레이어, 커스텀 에러, Notify
- [x] Phase 2: 프로토콜 확장 (R8, R2, R3, R9, R10) — HKDF, trait, DTO, 버전
- [x] Phase 3: CLI 현대화 (R5) — clap + 모듈화
- [ ] Phase 4: upload/download + SOCKS5 프록시
- [ ] Phase 5: 토큰 조작 + lateral movement
- [ ] Phase 6: BOF 로더
- [ ] Phase 7: Malleable C2 프로파일 고도화

### 최종 목표
CRTO 실습용 Cobalt Strike 워크플로우 재현. 학습 후 정식 CS 라이선스로 전환 예정.