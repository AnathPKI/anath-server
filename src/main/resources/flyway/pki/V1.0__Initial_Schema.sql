CREATE TABLE secure (
  id             BIGSERIAL,
  "key"          VARCHAR(512) NOT NULL UNIQUE,
  encrypted_data BYTEA        NOT NULL,
  iv             BYTEA,
  algo           VARCHAR(128) NOT NULL
);

CREATE TABLE certificates (
  id               NUMERIC(48)   NOT NULL UNIQUE,
  not_valid_before TIMESTAMP     NOT NULL,
  not_valid_after  TIMESTAMP     NOT NULL,
  subject          VARCHAR(2048) NOT NULL,
  x509_cert_pem    BYTEA         NOT NULL
);

