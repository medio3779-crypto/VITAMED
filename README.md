# VITAMED — PostgreSQL-ready starter

This package contains the VITAMED website, an Express API, and PostgreSQL account storage.

## Included
- `public/index.html`: the current VITAMED website.
- `server.js`: Express API with registration, login, current-user, and logout endpoints.
- PostgreSQL schema initialization on server startup. It safely creates `users` and its case-insensitive unique email index if they do not exist.

## Required environment variables
- `DATABASE_URL`: Neon pooled connection string. Keep it secret; never commit it to GitHub.
- `JWT_SECRET`: random secret of at least 32 characters.
- `NODE_ENV=production` when deployed.

## Deploy settings
- Build command: `npm install`
- Start command: `npm start`
- Node: 20 or newer

## API endpoints
- `POST /api/auth/register` with `{ "name", "email", "password" }`
- `POST /api/auth/login` with `{ "email", "password" }`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/health`

Passwords are hashed with bcrypt. Sessions use an HttpOnly cookie and JWT.

## Important current limitation
The supplied HTML is the existing public landing page. It does not yet contain login/register forms or a profile page wired to these API endpoints. The backend endpoints are prepared, but the visible account UI still needs to be added and connected in a follow-up update.
