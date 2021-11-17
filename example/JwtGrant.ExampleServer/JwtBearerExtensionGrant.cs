using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Test;
using IdentityServer4.Validation;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JwtGrant.ExampleServer;

internal sealed class JwtBearerExtensionGrant : IExtensionGrantValidator
{
    private readonly IHttpContextAccessor contextAccessor;
    private readonly TestUserStore userStore;

    public JwtBearerExtensionGrant(IHttpContextAccessor contextAccessor, TestUserStore userStore)
    {
        this.contextAccessor = contextAccessor;
        this.userStore = userStore;
    }

    public string GrantType => OidcConstants.GrantTypes.JwtBearer;

    public async Task ValidateAsync(ExtensionGrantValidationContext context)
    {
        var assertion = context.Request.Raw["assertion"];
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = await context.Request.Client.ClientSecrets.GetKeysAsync(),
            ValidateIssuerSigningKey = true,
            ValidIssuer = context.Request.ClientId,
            ValidateIssuer = true,
            ValidAudiences = new[] 
            {
                contextAccessor.HttpContext.GetIdentityServerIssuerUri() + "/connect/token",
            },
            ValidateAudience = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromMinutes(5.0)
        };
        try
        {
            new JwtSecurityTokenHandler().ValidateToken(assertion, validationParameters, out var validatedToken);
            var jwtToken = validatedToken as JwtSecurityToken;
            if (jwtToken is not null)
            {
                var user = userStore.FindByUsername(jwtToken.Subject);
                context.Result = new GrantValidationResult(subject: jwtToken.Subject, authenticationMethod: GrantType, user.Claims);
            }
        }
        catch
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest, "invalid request");
        }

    }
}

