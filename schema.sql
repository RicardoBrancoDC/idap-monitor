-- Estrutura D1 do IDAP Monitor V5
CREATE TABLE IF NOT EXISTS alerts (
    file TEXT PRIMARY KEY,
    file_date TEXT,
    uf TEXT,
    source_url TEXT,
    alert_id TEXT,
    identifier TEXT,
    sender TEXT,
    sender_name TEXT,
    institution TEXT,
    sent TEXT,
    effective TEXT,
    expires TEXT,
    event TEXT,
    severity TEXT,
    urgency TEXT,
    certainty TEXT,
    level TEXT,
    headline TEXT,
    area_desc TEXT,
    duration_minutes INTEGER,
    vigencia_auto TEXT,
    vigencia_note TEXT,
    texto_auto TEXT,
    texto_note TEXT,
    algorithm_version TEXT,
    parser_version INTEGER,
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
    file TEXT PRIMARY KEY,
    vig_choice TEXT,
    vig_correct_value TEXT,
    vig_reason TEXT,
    txt_choice TEXT,
    txt_correct_value TEXT,
    txt_reason TEXT,
    reviewer TEXT,
    algorithm_version_at_review TEXT,
    reviewed_at TEXT,
    vig_validated_value TEXT,
    txt_validated_value TEXT
);
CREATE TABLE IF NOT EXISTS custom_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT NOT NULL,
    normalized_term TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'human_learning',
    approved_by TEXT,
    approved_at TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(normalized_term, category)
);
CREATE TABLE IF NOT EXISTS evaluation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    dimension TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    result TEXT NOT NULL,
    note TEXT,
    evaluated_at TEXT NOT NULL,
    UNIQUE(file, dimension, algorithm_version)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
INSERT OR IGNORE INTO settings(key,value) VALUES('ruleset_revision','0');
CREATE INDEX IF NOT EXISTS idx_alerts_file_date ON alerts(file_date);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_uf ON alerts(uf);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewed_at ON reviews(reviewed_at);
