using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace ExternalApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string key = "{\"e\":\"AQAB\",\"key_ops\":[],\"kty\":\"RSA\",\"n\":\"izrfVteExpYaxLU2zcpq-DVytdm22jh63Tq--hbyiqKla-vOy4HF4IpOJMNcQ-p5yedLQL0LwIxUE4l7xuMIQmwQqBba3g7wevhM327uzI_8oqFVBIMsfmwkb_dug2zkpjtVgTjbQDbWyoM4cgeLpZcmdtAY6sdWMkGjjtNxqJiiWcOEW-p16wTeJSYRK8uhfMLNTQBdHae0XTdAVdXR0fGwc0UEqy5cwLRRD26VkU5arMn9qrwvW-ZxvFPVkseJ1f71w7pJIDAFjxkg8CIK_TwhwnC5NzRrcjbKdggQY-jhZtuJGpCAB7u2yWJQZ9TeblEYaAV0K4fVyonr88133w\",\"oth\":[],\"x5c\":[]}";
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
                                        JsonWebKey.Create(key)
                                    }
                                };

                                o.MapInboundClaims = false;
                            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.

            app.UseAuthentication();
            app.MapGet("/", (HttpContext ctx) =>
            {
                return ctx.User.FindFirst("sub")?.Value ?? "empty";
            });
            app.Run();
        }
    }
}
