# RoslynSecurityAnalyzer

A Roslyn-based security analyzer for **ASP.NET Core Web APIs**, evaluated against **VulnerableBankApi**, a deliberately vulnerable banking API with a ground-truth answer key.

The goal is not only to flag insecure code, but to **measure** how well each rule works: which real vulnerabilities it finds (recall) and how often it raises false alarms (precision).

> ⚠️ **VulnerableBankApi is intentionally insecure.** It exists only as a test target for the analyzer. Never deploy it or expose it to a network.

---

## Project layout

```
RoslynSecurityAnalyzer/
├── src/
│   └── RoslynSecurityAnalyzer/          # The analyzer (netstandard2.0)
├── tests/
│   └── RoslynSecurityAnalyzer.Tests/    # Unit tests for each rule (xUnit)
└── benchmarks/
    └── VulnerableBankApi/               # Evaluation target (.NET 10 Web API)
        └── ground-truth.md              # Answer key: planted bugs and safe controls
```

| Folder | Purpose |
|---|---|
| `src` | The analyzer. It runs inside the C# compiler and reports diagnostics during the build. |
| `tests` | Unit tests that compile small code snippets and check exactly where each rule fires. |
| `benchmarks` | A realistic API with planted vulnerabilities and deliberately safe look-alikes, used to score the analyzer. |

---

## Rules

| ID | Category | Severity | Detects | CWE |
|---|---|---|---|---|
| RSA001 | Security | Warning | SQL command text built from strings (concatenation or interpolation) instead of parameters | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |

Rule IDs follow the pattern `RSA` + number (**R**oslyn **S**ecurity **A**nalyzer).

---

## Benchmark: VulnerableBankApi

A small banking API (JWT login, accounts, transactions, admin) backed by SQLite. It contains:

- **8 planted vulnerabilities** (V1–V8) across 7 CWE categories
- **4 safe control cases** (S1–S4): code that looks similar to a vulnerability but is correct, used to measure false positives

The source code contains no hints about where the bugs are. The answer key lives only in [`ground-truth.md`](benchmarks/VulnerableBankApi/ground-truth.md), so the benchmark can also be used to evaluate tools or models that read the code.

| ID | Vulnerability | CWE | Detection difficulty |
|---|---|---|---|
| V1 | Hardcoded JWT signing key | CWE-798 | pattern |
| V2 | Weak password hashing (unsalted MD5) | CWE-916 | pattern |
| V3 | Password written to logs | CWE-532 | taint |
| V4 | Open redirect | CWE-601 | pattern |
| V5 | IDOR (missing ownership check) | CWE-639 | hard |
| V6 | SQL injection (string concatenation) | CWE-89 | taint |
| V7 | SQL injection (string interpolation) | CWE-89 | taint |
| V8 | Missing authorization on an admin action | CWE-862 | semantic |

**Difficulty levels**

| Level | Meaning |
|---|---|
| pattern | A syntax or API match is enough |
| semantic | Needs type, symbol or attribute reasoning |
| taint | Needs to follow user input to a dangerous call |
| hard | A business-logic flaw; most static analyzers miss these |

---

## Results

### Run 1 — RSA001

| ID | Expected | Result | Outcome |
|---|---|---|---|
| V6 | flag | RSA001 | ✅ True positive |
| V7 | flag | RSA001 | ✅ True positive |
| S1 | no flag | — | ✅ True negative |
| S2 | no flag | — | ✅ True negative |
| S3 | no flag | — | ✅ True negative |

| Scope | Recall | Precision |
|---|---|---|
| SQL injection (CWE-89) | 2 / 2 | 2 / 2 |
| Whole benchmark | 2 / 8 | 2 / 2 |

RSA001 detects both SQL injection styles (`+` concatenation and `$"..."` interpolation) and raises no warnings on the three parameterized queries. The remaining vulnerabilities are not yet covered by any rule. See the [roadmap](#roadmap).

Full scoring: [`ground-truth.md`](benchmarks/VulnerableBankApi/ground-truth.md#scoring)

---

## Getting started

**Requirements:** [.NET 10 SDK](https://dotnet.microsoft.com/download)

```bash
git clone <this-repo-url>
cd RoslynSecurityAnalyzer
dotnet build
```

### Run the unit tests

```bash
dotnet test
```

### Run the analyzer on the benchmark

The benchmark project already references the analyzer, so building it reports diagnostics:

```bash
dotnet build benchmarks/VulnerableBankApi --no-incremental
```

To show only this analyzer's warnings (PowerShell):

```powershell
dotnet build benchmarks/VulnerableBankApi --no-incremental | Select-String RSA
```

### Use the analyzer in another project

Add a project reference that loads it as an analyzer:

```xml
<ItemGroup>
  <ProjectReference Include="path/to/src/RoslynSecurityAnalyzer/RoslynSecurityAnalyzer.csproj"
                    OutputItemType="Analyzer"
                    ReferenceOutputAssembly="false" />
</ItemGroup>
```

Rule severity can be changed in `.editorconfig`, for example:

```ini
dotnet_diagnostic.RSA001.severity = error
```

### Run the benchmark API (local only)

```bash
cd benchmarks/VulnerableBankApi
dotnet run
```

It listens on `http://localhost:5247`. Seed users: `alice` and `bob` (customers), `admin` (administrator). The SQLite database `bank.db` is created on first run; delete it to reset the data.

---

## Roadmap

- [x] Benchmark API with ground truth (V1–V8, S1–S4)
- [x] RSA001: SQL built from strings (CWE-89)
- [ ] Rules for hardcoded secrets (CWE-798), weak password hashing (CWE-916) and sensitive data in logs (CWE-532)
- [ ] Rule for missing authorization on controller actions (CWE-862), including controller-level and global policies
- [ ] Compare with existing .NET security analyzers on the same benchmark
- [ ] Explore LLM-assisted detection for business-logic flaws such as IDOR (CWE-639)
- [ ] Extend the benchmark with more vulnerability categories

---

## Related work

Roslyn Security Guard and its successor Security Code Scan are established Roslyn-based security analyzers for .NET. Microsoft's built-in code analysis also includes security rules (for example CA2100 for SQL queries), and [CodeQL](https://codeql.github.com/) supports C#.

This project differs in its focus:

- **ASP.NET Core Web APIs**, including API-specific flaws such as missing authorization and IDOR
- **Measurement first**: every rule is scored against a benchmark with ground truth and safe control cases, reporting both recall and precision

---

## Author

**Saad Kabir Uddin** — Software engineer, Dhaka, Bangladesh
Portfolio: [saadkabiruddin.github.io](https://saadkabiruddin.github.io/)
