using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IdentityService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var privateKey = RSA.Create();
            privateKey.ImportRSAPrivateKey(privateKey.ExportRSAPrivateKey(), out _);

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
                            o =>
                            {
                                o.TokenValidationParameters = new TokenValidationParameters
                                {
                                    ValidateAudience = false,
                                    ValidateIssuer = false,
                                };

                                o.Events = new JwtBearerEvents()
                                {
                                    OnMessageReceived = (ctx) =>
                                    {
                                        if (ctx.Request.Query.ContainsKey("t"))
                                        {
                                            ctx.Token = ctx.Request.Query["t"];
                                        }

                                        return Task.CompletedTask;
                                    }
                                };

                                o.Configuration = new OpenIdConnectConfiguration()
                                {
                                    SigningKeys =
                                    {
                                        new RsaSecurityKey(privateKey)
                                    }
                                };

                                o.MapInboundClaims = false;
                            });

            var app = builder.Build();

            app.UseAuthentication();

            app.MapGet("/", (HttpContext ctx) =>
            {
                return ctx.User.FindFirst("sub")?.Value ?? "empty";
            });

            app.MapGet("/jwt", () =>
            {
                var handler = new JsonWebTokenHandler();
                var key = new RsaSecurityKey(privateKey);
                var token = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    Audience = "your_api_resource_id",
                    Issuer = "my_issuer",
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("sub", Guid.NewGuid().ToString()),
                        new Claim("name", "Denis")
                    }),
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
                });
                return token;
            });

            app.MapGet("/jwk", () =>
            {
                var publicKey = RSA.Create();
                publicKey.ImportRSAPublicKey(privateKey.ExportRSAPublicKey(), out _);
                var key = new RsaSecurityKey(publicKey);
                return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            });

            app.MapGet("/jwk-private", () =>
            {
                var key = new RsaSecurityKey(privateKey);
                return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            });

            app.Run(); 
        }
    }
}
