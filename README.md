# Namer

A tiny name generator. Tap **Generate** to get a random two-word name
(one adjective + one noun, e.g. "Silly Panda"), keep your own list of
everything you've generated, and **Share** any of them to a public Home
feed so everyone can see what names people are making.

## How it works

- **Sign-in** — the server verifies the platform-issued user token (an
  RS256 JWT) on every request, so the app already knows who's using it.
- **Generate** — `POST /api/generate` picks one random adjective and one
  random noun from a curated word list baked into `server.js` and saves
  the combination to your personal list.
- **My Names** — `GET /api/names` returns your own generated names,
  newest first, each with a Share button.
- **Share** — `POST /api/names/:id/share` marks one of your names as
  shared; sharing is one-way (no unshare in v1).
- **Home feed** — `GET /api/feed` returns every name any user has
  shared, newest first, with the sharer's username.

## Development

- `npm start` — run the server locally.
- `npm run build:css` — recompile `public/tailwind.css` from
  `styles/tailwind-input.css` (the Dockerfile does this automatically on
  every deploy).
