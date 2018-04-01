--
-- The secure store
--
CREATE TABLE secure (
  id             BIGSERIAL,
  key            VARCHAR(512) NOT NULL UNIQUE,
  encrypted_data BYTEA        NOT NULL,
  iv             BYTEA,
  algo           VARCHAR(128) NOT NULL
);

--
-- Certificate uses
--
CREATE TABLE certificate_uses (
  certificate_use VARCHAR(256) PRIMARY KEY,
  config          BYTEA
);

--
-- Certificates
--
CREATE TABLE certificates (
  id               BIGSERIAL,
  serial_number    NUMERIC(48)   NOT NULL UNIQUE,
  not_valid_before TIMESTAMP     NOT NULL,
  not_valid_after  TIMESTAMP     NOT NULL,
  -- The subject may not be UNIQUE, since uniqueness is only required for non-expired, non-revoked certificates
  subject          VARCHAR(2048) NOT NULL,
  status           VARCHAR(32)   NOT NULL,
  revoke_reason    VARCHAR(1024),
  -- The id from a foreign system identifying the user the certificate belongs to
  user_id          VARCHAR(128)  NOT NULL,
  x509_cert_pem    BYTEA         NOT NULL,
  certificate_use  VARCHAR(256)  NOT NULL REFERENCES certificate_uses (certificate_use)
);

INSERT INTO certificate_uses (certificate_use, config) VALUES ('plain', null);