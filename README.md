# Banking Auth Service

Authentication and authorization microservice for banking channels.

Built with **.NET 10**, JWT access tokens, refresh-token rotation, role-based access (`Customer` / `Teller` / `Admin`), and optional **TOTP 2FA**.

## Architecture

```mermaid
flowchart TD
    UI["Mobile / Web / Teller UI"] -->|HTTPS| API["BankingAuth.Api<br/>register · login · refresh · me"]
    API --> Service["AuthService"]
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
    User->>API: POST /api/auth/login
    API->>Svc: Verify email + password (PBKDF2)
    alt TOTP enabled
        Svc->>Svc: Verify TOTP code
    end
    Svc-->>API: Access token + refresh token
    API-->>User: 200 OK (tokens)
    User->>API: GET /api/me (Bearer token)
    API-->>User: Profile (role, totpEnabled)
```

## Features

- User registration with PBKDF2 password hashing (`Customer` / `Teller` only; Admin is not self-service)
- Login with JWT access token (30 minutes) + refresh token (7 days)
- Refresh-token rotation (old token revoked after use)
- TOTP setup + confirmation (Google Authenticator compatible)
- Role-protected admin endpoint
- OpenAPI document included

## Domain model

Class-level view of the main types and how they relate (fields, operations and dependencies).

```mermaid
classDiagram
    direction TB
    class AuthService {
        -_usersByEmail: Dictionary~string, UserAccount~
        -_refreshTokens: Dictionary~string, RefreshToken~
        +Register(request) UserAccount
        +EnsureAdmin(email, password) UserAccount
        +Login(request) TokenResponse
        +Refresh(refreshToken) TokenResponse
        +BeginEnableTotp(userId) EnableTotpResponse
        +ConfirmEnableTotp(userId, code) void
        +GetProfile(userId) UserAccount
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
    AuthService o-- UserAccount
    AuthService o-- RefreshToken
    AuthService ..> PasswordHasher
    UserAccount --> UserRole
    AuthService ..> RegisterRequest
    AuthService ..> LoginRequest
    AuthService ..> TokenResponse
    AuthService ..> EnableTotpResponse
```

## Quick start

```bash
dotnet restore
dotnet test
dotnet run --project BankingAuth.Api
```

API base URL (HTTP): `http://localhost:5049`

Admin bootstrap (Development): on startup the API seeds
`Admin:Email` / `Admin:Password` from config (defaults `admin@example.com` / `Admin123!`)
via `EnsureAdmin`. Use that account for `GET /api/admin/ping`.

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
| `POST` | `/api/auth/totp/setup` | Yes | Begin TOTP enrollment |
| `POST` | `/api/auth/totp/confirm` | Yes | Confirm TOTP |
| `GET` | `/api/me` | Yes | Current profile |
| `GET` | `/api/admin/ping` | Admin | Role check |
| `GET` | `/health` | No | Health check |

## Security notes

- Demo storage is in-memory (restart clears users)
- Replace the JWT signing key before any shared deployment
- TOTP uses a 1-step verification window

## Tests

```bash
dotnet test
```

## License

MIT — see [LICENSE](LICENSE).

<!-- docs: maintenance pass 2026-05-18 -->
