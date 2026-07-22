# Banking Auth Service

An MVP authentication and authorization service for a banking-style backend. It is a learning /
portfolio project, not a production bank system: treat it as a solid starting point for JWT +
refresh-token auth with role-based access, not as a finished product.

Built with **.NET 10**, JWT access tokens, refresh-token rotation, role-based access
(`Customer` / `Teller` / `Admin`), optional **TOTP 2FA**, and **EF Core + SQLite** for durable
storage (a file-based database, no external DB server needed).

## Architecture

```mermaid
flowchart TD
    UI["Mobile / Web / Teller UI"] -->|HTTPS| API["BankingAuth.Api<br/>register · login · refresh · me"]
    API --> Service["AuthService"]
    Service --> DB[("SQLite<br/>bankingauth.db")]
    Service --> Hash["PBKDF2 password hash"]
    Service --> JWT["JWT access token · 30m"]
    Service --> Refresh["Refresh token · 7d<br/>rotated on use"]
    Service --> TOTP["TOTP · optional 2FA"]
    JWT --> Roles{"Role check"}
    Roles -->|Customer| C["Customer APIs"]
    Roles -->|Teller| T["Teller APIs"]
    Roles -->|Admin| A["/api/admin/ping"]
```

Login flow:

```mermaid
sequenceDiagram
    actor User
    participant API as BankingAuth.Api
    participant Svc as AuthService
    participant DB as SQLite
    User->>API: POST /api/auth/login
    API->>Svc: Verify email + password (PBKDF2)
    Svc->>DB: Look up user, check lockout
    alt TOTP enabled
        Svc->>Svc: Verify TOTP code
    end
    Svc->>DB: Persist refresh token / lockout state
    Svc-->>API: Access token + refresh token
    API-->>User: 200 OK (tokens)
    User->>API: GET /api/me (Bearer token)
    API-->>User: Profile (role, totpEnabled)
```

## Features

- User registration with PBKDF2 password hashing (`Customer` / `Teller` only; Admin is not
  self-service, it is seeded from config on startup)
- Login with JWT access token (30 minutes) + refresh token (7 days)
- Refresh-token rotation (old token revoked, new one issued, in a single DB transaction)
- TOTP setup + confirmation (Google Authenticator compatible)
- Role-protected Customer, Teller and Admin demonstration endpoints
- Five-failure, 15-minute account lockout and letter-plus-digit password policy
- Refresh-token logout/revocation and security response headers
- Durable storage via EF Core + SQLite (users and refresh tokens survive a restart)
- OpenAPI document mapped in every environment

## Diagrams

Architecture and UML diagrams are in [docs/architecture.md](docs/architecture.md) and [docs/uml.md](docs/uml.md). A standalone index is available at [docs/index.html](docs/index.html).

```mermaid
classDiagram
    direction TB
    class AuthService {
        -_db: AuthDbContext
        +Register(request) UserAccount
        +EnsureAdmin(email, password) UserAccount
        +Login(request) TokenResponse
        +Refresh(refreshToken) TokenResponse
        +Logout(refreshToken) void
        +BeginEnableTotp(userId) EnableTotpResponse
        +ConfirmEnableTotp(userId, code) void
        +GetProfile(userId) UserAccount
    }
    class AuthDbContext {
        +Users: DbSet~UserAccount~
        +RefreshTokens: DbSet~RefreshToken~
    }
    class PasswordHasher {
        <<utility>>
        +Hash(password) string
        +Verify(password, hash) bool
    }
    class UserAccount {
        +UserId: string
        +Email: string
        +PasswordHash: string
        +Role: UserRole
        +TotpSecret: string
        +TotpEnabled: bool
        +CreatedAt: DateTimeOffset
    }
    class RefreshToken {
        +Token: string
        +UserId: string
        +ExpiresAt: DateTimeOffset
        +Revoked: bool
    }
    class UserRole {
        <<enumeration>>
        Customer
        Teller
        Admin
    }
    class RegisterRequest {
        +Email: string
        +Password: string
        +Role: string
    }
    class LoginRequest {
        +Email: string
        +Password: string
        +TotpCode: string
    }
    class TokenResponse {
        +AccessToken: string
        +RefreshToken: string
        +ExpiresAt: DateTimeOffset
        +RequiresTotp: bool
    }
    class EnableTotpResponse {
        +SharedSecret: string
        +OtpAuthUri: string
    }
    AuthService --> AuthDbContext
    AuthDbContext o-- UserAccount
    AuthDbContext o-- RefreshToken
    AuthService ..> PasswordHasher
    UserAccount --> UserRole
    AuthService ..> RegisterRequest
    AuthService ..> LoginRequest
    AuthService ..> TokenResponse
    AuthService ..> EnableTotpResponse
```

## Quick start (local .NET)

```bash
dotnet restore
dotnet test
dotnet run --project BankingAuth.Api
```

API base URL (HTTP): `http://localhost:5049`

On startup the API creates the SQLite schema if it doesn't exist yet
(`BankingAuth.Api/bankingauth.db`, gitignored) and seeds an Admin account from
`Admin:Email` / `Admin:Password` (defaults `admin@example.com` / `Admin123!`) via
`EnsureAdmin`. Use that account for `GET /api/admin/ping`.

The `Jwt:SigningKey` used in Development comes from `appsettings.Development.json`
(a placeholder value, fine for local use only). Outside Development the API **requires**
`Jwt:SigningKey` / `Jwt__SigningKey` to be set explicitly and refuses to start otherwise -
see [Security notes](#security-notes).

## Run with Docker

```bash
echo "JWT_SIGNING_KEY=replace-with-a-long-random-secret-at-least-32-chars" > .env
docker compose up --build
```

This builds the API image and runs it on `http://localhost:8080`, with the SQLite file
persisted in the `banking-auth-data` named volume (mounted at `/data` in the container), so
data survives `docker compose down` / `up` cycles. `JWT_SIGNING_KEY` is required; the container
fails fast on startup if it's missing (see `docker-compose.yml`).

## Example flow

```bash
# Register (Customer or Teller only)
curl -s -X POST http://localhost:5049/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"alice@example.com\",\"password\":\"Secret123!\",\"role\":\"Customer\"}"

# Login
curl -s -X POST http://localhost:5049/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"alice@example.com\",\"password\":\"Secret123!\"}"

# Profile (Bearer access token)
curl -s http://localhost:5049/api/me -H "Authorization: Bearer <access_token>"
```

### Enable 2FA

1. Login and call `POST /api/auth/totp/setup` with Bearer token
2. Scan / enter `sharedSecret` in an authenticator app
3. Confirm with `POST /api/auth/totp/confirm` `{ "code": "123456" }`
4. Later logins require `totpCode` in the login body

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/register` | No | Create user |
| `POST` | `/api/auth/login` | No | Issue tokens |
| `POST` | `/api/auth/refresh` | No | Rotate refresh token |
| `POST` | `/api/auth/logout` | No | Revoke a refresh token |
| `POST` | `/api/auth/totp/setup` | Yes | Begin TOTP enrollment |
| `POST` | `/api/auth/totp/confirm` | Yes | Confirm TOTP |
| `GET` | `/api/me` | Yes | Current profile |
| `GET` | `/api/admin/ping` | Admin | Role check |
| `GET` | `/api/customer/accounts/summary` | Customer or Admin | Mock account summary |
| `GET` | `/api/teller/customers/lookup?email=` | Teller or Admin | Mock customer lookup |
| `GET` | `/health` | No | Health check |

## Security notes

- Storage is SQLite via EF Core; refresh-token rotation runs inside an explicit DB transaction
  so a crash mid-rotation can't leave an old token revoked without a new one issued
- `Jwt:SigningKey` has **no fallback outside Development** - the app throws on startup if it's
  missing, instead of silently signing tokens with a weak default. In Development it falls back
  to a placeholder key (`appsettings.Development.json`) purely so `dotnet run` works out of the box
- Replace `Jwt:SigningKey` and the Admin bootstrap password before any shared/public deployment
- TOTP uses a 1-step verification window

## Tests

```bash
dotnet test
```

Includes unit tests for `AuthService`/`PasswordHasher`, `WebApplicationFactory`-based integration
tests for role isolation and security headers, and dedicated persistence tests that register a
user or issue a refresh token in one `AuthDbContext`/`WebApplicationFactory` instance, then open a
brand new one against the same SQLite file (simulating a restart) and prove login/refresh still
work. Every test class uses its own temp SQLite file so tests never share state.

CI (`.github/workflows/ci.yml`) restores, builds and runs the full test suite on `ubuntu-latest`
for every push/PR to `main`.

## License

MIT — see [LICENSE](LICENSE).
