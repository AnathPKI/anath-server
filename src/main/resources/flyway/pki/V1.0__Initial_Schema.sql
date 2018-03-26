CREATE TABLE secure (
  id             BIGSERIAL,
  key            VARCHAR(512) NOT NULL UNIQUE,
  encrypted_data BYTEA        NOT NULL,
  iv             BYTEA,
  algo           VARCHAR(128) NOT NULL
);

CREATE TABLE certificates (
  id               BIGSERIAL,
  serial_number    NUMERIC(48)   NOT NULL UNIQUE,
  not_valid_before TIMESTAMP     NOT NULL,
  not_valid_after  TIMESTAMP     NOT NULL,
  subject          VARCHAR(2048) NOT NULL UNIQUE,
  status           VARCHAR(32)   NOT NULL,
  -- The id from a foreign system identifying the user the certificate belongs to
  user_id          VARCHAR(128)  NOT NULL,
  x509_cert_pem    BYTEA         NOT NULL,
);

