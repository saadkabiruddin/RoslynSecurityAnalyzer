using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VulnerableBankApi.Data;
using VulnerableBankApi.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<Db>();
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AppSecrets.JwtSigningKey))
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.Services.GetRequiredService<Db>().Initialize();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();