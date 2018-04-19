CREATE TABLE users (
  id        BIGSERIAL,
  firstname VARCHAR(512)  NOT NULL,
  lastname  VARCHAR(512)  NOT NULL,
  email     VARCHAR(1024) NOT NULL UNIQUE,
  password  VARCHAR(1024) NOT NULL,
  admin     BOOLEAN       NOT NULL DEFAULT 'f'
);
