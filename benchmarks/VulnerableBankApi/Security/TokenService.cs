using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace VulnerableBankApi.Security;

public static class TokenService
{
    public static string Create(long userId, string role)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AppSecrets.JwtSigningKey));
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                [ClaimTypes.NameIdentifier] = userId.ToString(),
                [ClaimTypes.Role] = role
            },
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}

public static class ClaimsPrincipalExtensions
{
    public static long GetUserId(this ClaimsPrincipal user) =>
        long.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)
                   ?? throw new InvalidOperationException("User id claim missing."));
}