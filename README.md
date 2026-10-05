# Khan Homemade Store

Mobile-first, English-language storefront for homemade sewing, clothing, food, and decor. The project uses a plain HTML/CSS/JavaScript front end, a Cloudflare Worker API, PostgreSQL persistence through Neon’s serverless driver, R2 product-image storage, and optional Resend order email.

## Included

- Home, Shop (live search and category filters), Product detail/order form, About, Contact, Owner sign-in, and owner dashboard.
- Buyers do not log in. Orders are saved first, then the browser opens the selected owner’s WhatsApp chat with a prepared order message and product link.
- Owner sign-in asks for the registered 10-digit phone and the owner-panel password. The password is checked only by the Worker against `OWNER_PANEL_PASSWORD`; it is not embedded in browser code. Login attempts are rate-limited.
- The signed, HTTP-only session is revalidated against an active database owner on every owner API request. The primary owner can manage all products, orders, and owner records; other owners can access only their own products and orders.
- Product images are uploaded to the configured R2 bucket. Product hiding and owner removal are soft operations so historic orders stay intact; deactivated owners cannot sign in.
- The initial SQL seeds only the supplied primary owner. It does not invent products, prices, or stock.

## Required service configuration

The project contains no service credentials. PostgreSQL is required for database-backed owner login, products, and orders.

| Name | Type | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Worker secret | PostgreSQL connection string for Neon or a compatible PostgreSQL endpoint supported by `@neondatabase/serverless`. |
| `OWNER_PANEL_PASSWORD` | Worker secret | Shared owner-panel password; a successful login also requires the submitted phone to belong to an active owner record. |
| `SESSION_SECRET` | Worker secret | Random HMAC signing key for owner sessions; use at least 32 characters. |
| `RESEND_API_KEY` | Worker secret | Optional transactional email API key. Without it, order saving and WhatsApp still work, but no email is sent. |
| `RESEND_FROM_EMAIL` | Wrangler variable | Sender address verified in Resend; replace the example before enabling email. |
| `PRODUCT_IMAGES` | Cloudflare R2 binding | Binding to the `khan-homemade-product-images` bucket declared in `wrangler.toml`. |

The fallback WhatsApp destination is `+91 93247 93621`; a product owner’s WhatsApp number takes precedence when set. The main-owner email is `irshadkhan8879920195@gmail.com`.

## PostgreSQL setup

1. Create a PostgreSQL database and configure `DATABASE_URL`.
2. Apply `schema.sql` once with a trusted SQL client, for example: `psql "$DATABASE_URL" -f schema.sql`.
3. The schema seeds the primary owner phone `9082590422` and email `irshadkhan8879920195@gmail.com`. Owner login remains unavailable until this database is configured and reachable.

## Cloudflare setup

1. Create the R2 bucket named `khan-homemade-product-images` in the deployment account.
2. Set the Worker secrets with `npx wrangler secret put SECRET_NAME` (repeat for `DATABASE_URL`, `OWNER_PANEL_PASSWORD`, `SESSION_SECRET`, and any optional secret).
3. Set `RESEND_FROM_EMAIL` to a sender identity verified with Resend before enabling email.
4. Deploy with `npx wrangler deploy` after the account, Worker, and R2 setup is available.

## Local development and checks

- Install packages with `npm install`.
- Run static syntax checks with `npm run check`.
- For local Worker development, copy `.dev.vars.example` to `.dev.vars` and fill the values in that ignored local file, then run `npx wrangler dev --local`.
- `.dev.vars` is ignored by Git and must never be included in a source archive or served from `public/`.

A temporary preview without PostgreSQL can display the storefront, but database-backed owner login and store data remain unavailable until PostgreSQL is configured. No authentication bypass or demo owner data is provided.

The storefront uses a warm, craft-inspired shop theme. Images in `public/images/` are illustrative category art, not verified product listings; replace them with rights-cleared store photos before public marketing use. Owner-uploaded product images go to R2.
