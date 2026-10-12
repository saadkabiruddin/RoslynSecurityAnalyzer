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

## Safe control cases

The analyzer should **not** flag these.

| ID | What it tests | CWE | File | Member | Why it's safe |
|---|---|---|---|---|---|
| S1 | SQL query | CWE-89 | Controllers/AuthController.cs | `AuthController.Login` (the query) | Username is passed as a parameter. |
| S2 | SQL query + ownership | CWE-89 / CWE-639 | Controllers/AccountsController.cs | `AccountsController.GetMine` | Parameterized, and filtered by the user id from the token. |

## Exploits (proof each bug is real)

| ID | How to trigger | Expected result |
|---|---|---|
| V1 | Sign a token with the key from `AppSecrets.cs` and `Role = Admin` | API accepts the forged token |
| V3 | Log in as alice | Console shows `with password alice123` |
| V4 | `GET /api/auth/logout?returnUrl=https://example.org` | Browser is redirected to example.org |
| V5 | As alice: `GET /api/accounts/2` | Returns Bob's account |
| V6 | As alice: `GET /api/accounts/search?accountNo=x' OR 1=1 --` (URL-encoded) | Returns all 3 accounts |

## Scoring (fill in after running the analyzer)

| ID | Expected | Analyzer flagged? | Outcome |
|---|---|---|---|
| V1 | flag | | |
| V2 | flag | | |
| V3 | flag | | |
| V4 | flag | | |
| V5 | flag | | |
| V6 | flag | | |
| S1 | no flag | | |
| S2 | no flag | | |

Outcome is one of: **TP** (true positive: real bug flagged), **FN** (false negative: real bug missed), **FP** (false positive: safe code flagged), **TN** (true negative: safe code left alone).
