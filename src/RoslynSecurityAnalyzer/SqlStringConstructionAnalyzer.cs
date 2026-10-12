using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace RoslynSecurityAnalyzer;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SqlStringConstructionAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "RSA001";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        "SQL contains a dynamically built string",
        "Use SQL parameters instead of building command text from strings",
        "Security",
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "String concatenation or interpolation in SQL command text can allow SQL injection.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeCreation, SyntaxKind.ObjectCreationExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;
        if (context.SemanticModel.GetSymbolInfo(assignment.Left).Symbol is not IPropertySymbol property ||
            property.Name != "CommandText" || !IsCommandType(property.ContainingType))
            return;

        if (IsDynamicString(context.SemanticModel.GetOperation(assignment.Right), 0))
            context.ReportDiagnostic(Diagnostic.Create(Rule, assignment.Right.GetLocation()));
    }

    private static void AnalyzeCreation(SyntaxNodeAnalysisContext context)
    {
        var creation = (ObjectCreationExpressionSyntax)context.Node;
        if (!IsCommandType(context.SemanticModel.GetTypeInfo(creation).Type) ||
            context.SemanticModel.GetOperation(creation) is not IObjectCreationOperation operation)
            return;

        foreach (var argument in operation.Arguments)
        {
            if (argument.Parameter?.Ordinal == 0 && argument.Parameter.Type.SpecialType == SpecialType.System_String &&
                IsDynamicString(argument.Value, 0))
            {
                context.ReportDiagnostic(Diagnostic.Create(Rule, argument.Syntax.GetLocation()));
                break;
            }
        }
    }

    private static bool IsCommandType(ITypeSymbol? type)
    {
        for (var current = type; current != null; current = current.BaseType)
            if (current.ToDisplayString() == "System.Data.Common.DbCommand")
                return true;
        return false;
    }

    private static bool IsDynamicString(IOperation? operation, int depth)
    {
        if (operation == null || depth > 8 || operation.ConstantValue.HasValue)
            return false;

        switch (operation)
        {
            case IConversionOperation conversion:
                return IsDynamicString(conversion.Operand, depth + 1);
            case IParenthesizedOperation parenthesized:
                return IsDynamicString(parenthesized.Operand, depth + 1);
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                    if (part is IInterpolationOperation interpolation &&
                        interpolation.Expression.Type?.SpecialType == SpecialType.System_String &&
                        !interpolation.Expression.ConstantValue.HasValue)
                        return true;
                return false;
            case IBinaryOperation binary when binary.OperatorKind == BinaryOperatorKind.Add &&
                                                   binary.Type?.SpecialType == SpecialType.System_String:
                return ContainsDynamicStringValue(binary.LeftOperand) || ContainsDynamicStringValue(binary.RightOperand);
            case ILocalReferenceOperation local:
                foreach (var reference in local.Local.DeclaringSyntaxReferences)
                    if (reference.GetSyntax() is VariableDeclaratorSyntax variable && variable.Initializer != null &&
                        IsDynamicString(local.SemanticModel?.GetOperation(variable.Initializer.Value), depth + 1))
                        return true;
                return false;
            default:
                return false;
        }
    }

    private static bool ContainsDynamicStringValue(IOperation operand)
    {
        if (operand is IBinaryOperation binary && binary.OperatorKind == BinaryOperatorKind.Add &&
            binary.Type?.SpecialType == SpecialType.System_String)
            return ContainsDynamicStringValue(binary.LeftOperand) || ContainsDynamicStringValue(binary.RightOperand);

        return operand.Type?.SpecialType == SpecialType.System_String && !operand.ConstantValue.HasValue;
    }
}
