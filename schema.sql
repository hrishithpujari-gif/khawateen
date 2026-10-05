-- Khan Homemade Store: PostgreSQL schema (run once against the configured database).
BEGIN;

CREATE TABLE IF NOT EXISTS owners (
  id BIGSERIAL PRIMARY KEY,
  phone VARCHAR(10) NOT NULL UNIQUE CHECK (phone ~ '^[0-9]{10}$'),
  email VARCHAR(254),
  whatsapp_phone VARCHAR(15) CHECK (whatsapp_phone IS NULL OR whatsapp_phone ~ '^[0-9]{10,15}$'),
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS owners_single_primary_idx ON owners (is_primary) WHERE is_primary = TRUE;

CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  category VARCHAR(20) NOT NULL CHECK (category IN ('silai','kapde','khana','decor')),
  price NUMERIC(10,2) NOT NULL CHECK (price > 0),
  description VARCHAR(1000) NOT NULL,
  image VARCHAR(80),
  in_stock BOOLEAN NOT NULL DEFAULT TRUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  owner_id BIGINT NOT NULL REFERENCES owners(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS products_active_created_idx ON products (is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS products_owner_idx ON products (owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
  product_name VARCHAR(100) NOT NULL,
  unit_price NUMERIC(10,2) NOT NULL CHECK (unit_price > 0),
  quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  buyer_name VARCHAR(80) NOT NULL,
  city VARCHAR(80) NOT NULL,
  owner_id BIGINT NOT NULL REFERENCES owners(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS orders_owner_created_idx ON orders (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS orders_product_idx ON orders (product_id);

CREATE TABLE IF NOT EXISTS owner_login_attempts (
  id BIGSERIAL PRIMARY KEY,
  phone VARCHAR(10) NOT NULL CHECK (phone ~ '^[0-9]{10}$'),
  ip_hash VARCHAR(43) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS owner_login_attempts_phone_created_idx ON owner_login_attempts (phone, created_at DESC);
CREATE INDEX IF NOT EXISTS owner_login_attempts_ip_created_idx ON owner_login_attempts (ip_hash, created_at DESC);

-- The supplied main-owner number is the only initial account. No sample product or price is fabricated.
INSERT INTO owners (phone, email, is_primary, is_active)
VALUES ('9082590422', 'irshadkhan8879920195@gmail.com', TRUE, TRUE)
ON CONFLICT (phone) DO UPDATE SET email=EXCLUDED.email, is_primary=TRUE, is_active=TRUE;

COMMIT;
