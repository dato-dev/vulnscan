-- Схема истории проверок (ROADMAP M4.2, docs/architecture.md §11).
--
-- Имя исходного файла здесь НЕ хранится. В потоке сканов паспортов и договоров
-- оно почти всегда содержит персональные данные, а для трассировки хватает
-- `scan_id` и `sha256`. По той же причине нет ни извлечённого текста, ни
-- метаданных документа.

CREATE TABLE IF NOT EXISTS files (
    sha256          char(64)    PRIMARY KEY,
    size            bigint      NOT NULL,
    detected_mime   text,
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id              uuid        PRIMARY KEY,
    sha256          char(64)    NOT NULL REFERENCES files(sha256),
    tenant          text,
    status          text        NOT NULL,
    verdict         text        NOT NULL,
    score           integer     NOT NULL DEFAULT 0,
    rules_version   text,
    av_db_version   text,
    policy_version  text,
    elapsed_ms      integer,
    -- Углублённая проверка ссылается на быструю, из которой выросла.
    parent_scan_id  uuid,
    deep            boolean     NOT NULL DEFAULT false,
    shadow          boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- По sha256 ищут историю конкретного файла, по created_at — выборки за период
-- и уборку старого. Оба запроса частые, оба без индекса деградируют линейно.
CREATE INDEX IF NOT EXISTS scans_sha256_idx     ON scans (sha256);
CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS scans_tenant_idx     ON scans (tenant, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_verdict_idx    ON scans (verdict, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    scan_id     uuid    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage       text    NOT NULL,
    code        text    NOT NULL,
    severity    text,
    score       integer NOT NULL DEFAULT 0,
    detail      text,
    PRIMARY KEY (scan_id, stage, code)
);

CREATE INDEX IF NOT EXISTS findings_code_idx ON findings (code);

CREATE TABLE IF NOT EXISTS artifacts (
    scan_id          uuid        PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    profile          text        NOT NULL,
    bucket           text        NOT NULL,
    key              text        NOT NULL,
    sanitized_sha256 char(64),
    expires_at       timestamptz
);
