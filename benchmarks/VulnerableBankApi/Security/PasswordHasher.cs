using System.Security.Cryptography;
using System.Text;

namespace VulnerableBankApi.Security;

public static class PasswordHasher
{
    public static string Hash(string password)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(bytes);
    }
}
