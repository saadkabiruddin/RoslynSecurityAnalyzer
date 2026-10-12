using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.Data.Sqlite;
using RoslynSecurityAnalyzer;

namespace RoslynSecurityAnalyzer.Tests;

public class SqlStringConstructionAnalyzerTests
{
    [Fact]
    public async Task ReportsConcatenatedSqlPassedThroughLocal()
    {
        const string source = """
            using Microsoft.Data.Sqlite;
            class Test {
                void Run(SqliteConnection connection, string accountNo) {
                    var sql = "SELECT * FROM Accounts WHERE AccountNo = '" + accountNo + "'";
                    using var cmd = new SqliteCommand(sql, connection);
                }
            }
            """;

        var diagnostic = Assert.Single(await Analyze(source));
        Assert.Equal(SqlStringConstructionAnalyzer.DiagnosticId, diagnostic.Id);
        Assert.Equal(5, diagnostic.Location.GetLineSpan().StartLinePosition.Line + 1);
    }

    [Fact]
    public async Task ReportsInterpolatedCommandText()
    {
        const string source = """
            using Microsoft.Data.Sqlite;
            class Test {
                void Run(SqliteCommand cmd, string query) {
                    cmd.CommandText = $"SELECT * FROM Transactions WHERE Description LIKE '%{query}%'";
                }
            }
            """;

        Assert.Single(await Analyze(source));
    }

    [Fact]
    public async Task IgnoresConstantAndParameterizedSql()
    {
        const string source = """
            using Microsoft.Data.Sqlite;
            class Test {
                void Run(SqliteConnection connection, string accountNo) {
                    using var cmd = new SqliteCommand("SELECT * FROM Accounts WHERE AccountNo = $accountNo", connection);
                    cmd.Parameters.AddWithValue("$accountNo", accountNo);
                    cmd.CommandText = "SELECT * FROM Accounts WHERE Id = " + "1";
                }
            }
            """;

        Assert.Empty(await Analyze(source));
    }

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source);
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Select(path => MetadataReference.CreateFromFile(path))
            .Concat(new[] { MetadataReference.CreateFromFile(typeof(SqliteCommand).Assembly.Location) });
        var compilation = CSharpCompilation.Create("AnalyzerTest", new[] { syntaxTree }, references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        return await compilation.WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new SqlStringConstructionAnalyzer()))
            .GetAnalyzerDiagnosticsAsync();
    }
}
