# Ground Truth: Vulnerable Bank API

Answer key for evaluating the security analyzer. Every planted vulnerability (V) and every deliberately safe control case (S) is listed here. The source code itself contains no hints.

**Detection difficulty**
- **pattern**: a simple syntax or API match is enough
- **semantic**: needs type, symbol or attribute reasoning
- **taint**: needs to follow user input from a parameter to a dangerous call
- **hard**: business-logic flaw; most static analyzers miss it

## Vulnerabilities

| ID | Vulnerability | CWE | File | Member | Difficulty | Why it's vulnerable |
|---|---|---|---|---|---|---|
| V1 | Hardcoded secret (JWT signing key) | CWE-798 | Security/AppSecrets.cs | `AppSecrets.JwtSigningKey` | pattern | Anyone with the source can forge tokens, including the Admin role. |
| V2 | Weak password hashing (unsalted MD5) | CWE-916 | Security/PasswordHasher.cs | `PasswordHasher.Hash` | pattern | MD5 is fast and unsalted, so leaked hashes are cracked quickly. |
| V3 | Password written to logs | CWE-532 | Controllers/AuthController.cs | `AuthController.Login` | taint | `request.Password` is passed to `logger.LogInformation`. |
| V4 | Open redirect | CWE-601 | Controllers/AuthController.cs | `AuthController.Logout` | pattern | `Redirect(returnUrl)` with unvalidated user input. |
| V5 | IDOR (missing ownership check) | CWE-639 | Controllers/AccountsController.cs | `AccountsController.GetById` | hard | Query filters by `Id` only; any logged-in user can read any account. |
| V6 | SQL injection (string concatenation) | CWE-89 | Controllers/AccountsController.cs | `AccountsController.Search` | taint | `accountNo` is concatenated into SQL; `--` can remove the ownership check. Note: the concatenated `User.GetUserId()` is not exploitable. |
| V7 | SQL injection (string interpolation) | CWE-89 | Controllers/TransactionsController.cs | `TransactionsController.Search` | taint | `q` is interpolated into `CommandText` with `$"..."`; `' OR 1=1 --` bypasses the ownership check. The interpolated `accountId` and `User.GetUserId()` are `long` and not exploitable. |
| V8 | Missing authorization | CWE-862 | Controllers/AdminController.cs | `AdminController.AdjustBalance` | semantic | No `[Authorize]` on the action or the controller, so anonymous users can change any account balance. |

## Safe control cases

The analyzer should **not** flag these.

| ID | What it tests | CWE | File | Member | Why it's safe |
|---|---|---|---|---|---|
| S1 | SQL query | CWE-89 | Controllers/AuthController.cs | `AuthController.Login` (the query) | Username is passed as a parameter. |
| S2 | SQL query + ownership | CWE-89 / CWE-639 | Controllers/AccountsController.cs | `AccountsController.GetMine` | Parameterized, and filtered by the user id from the token. |
| S3 | SQL query + ownership | CWE-89 / CWE-639 | Controllers/TransactionsController.cs | `TransactionsController.Recent` | Parameterized (including `LIMIT`), and filtered by the user id from the token. |
| S4 | Role-based authorization | CWE-862 | Controllers/AdminController.cs | `AdminController.ListUsers` | `[Authorize(Roles = "Admin")]` on the action: anonymous gets 401, customers get 403. |

## Exploits (proof each bug is real)

| ID | How to trigger | Expected result |
|---|---|---|
| V1 | Sign a token with the key from `AppSecrets.cs` and `Role = Admin` | API accepts the forged token |
| V3 | Log in as alice | Console shows `with password alice123` |
| V4 | `GET /api/auth/logout?returnUrl=https://example.org` | Browser is redirected to example.org |
| V5 | As alice: `GET /api/accounts/2` | Returns Bob's account |
| V6 | As alice: `GET /api/accounts/search?accountNo=x' OR 1=1 --` (URL-encoded) | Returns all 3 accounts |
| V7 | As alice: `GET /api/transactions?accountId=1&q=' OR 1=1 --` (URL-encoded) | Returns Bob's transaction (Mobile recharge) |
| V8 | With no token: `POST /api/admin/accounts/1/adjust-balance` with `{ "amount": 1000000, "reason": "x" }` | 204 No Content; alice's balance goes up by 1,000,000 |

## Scoring

**Run 1, 2026-10-12: RSA001 only.** SQL injection (CWE-89): recall 2/2, precision 2/2. Whole benchmark: 2 of 8 vulnerabilities detected, 0 false positives.

| ID | Expected | Analyzer flagged? | Outcome |
|---|---|---|---|
| V1 | flag | No (no rule yet) | FN |
| V2 | flag | No (no rule yet) | FN |
| V3 | flag | No (no rule yet) | FN |
| V4 | flag | No (no rule yet) | FN |
| V5 | flag | No (no rule yet) | FN |
| V6 | flag | RSA001 at AccountsController.cs(42,43) | TP |
| V7 | flag | RSA001 at TransactionsController.cs(19,27) | TP |
| V8 | flag | No (no rule yet) | FN |
| S1 | no flag | No | TN |
| S2 | no flag | No | TN |
| S3 | no flag | No | TN |
| S4 | no flag | No | TN |

Outcome is one of: **TP** (true positive: real bug flagged), **FN** (false negative: real bug missed), **FP** (false positive: safe code flagged), **TN** (true negative: safe code left alone).
