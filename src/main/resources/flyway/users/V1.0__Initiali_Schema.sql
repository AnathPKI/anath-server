create table users (
  id       BIGSERIAL,
  email    VARCHAR(1024) NOT NULL UNIQUE,
  password VARCHAR(1024) NOT NULL,
  admin    BOOLEAN       NOT NULL DEFAULT 'f'
);
