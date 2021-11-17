using JwtGrant.ExampleServer;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthorization();

builder
    .Services
    .AddIdentityServer()
    .AddInMemoryClients(new []
    {
        new Client() 
        { 
            ClientId = "client.jwt",
            ClientSecrets =
            {             
                new()
                {
                    Type = IdentityServerConstants.SecretTypes.SharedSecret,
                    Value = "secret".Sha256(),
                },
                new()
                {
                    Type = IdentityServerConstants.SecretTypes.JsonWebKey,
                    Value = "{'e':'AQAB','kid':'ZzAjSnraU3bkWGnnAqLapYGpTyNfLbjbzgAPbbW2GEA','kty':'RSA','n':'wWwQFtSzeRjjerpEM5Rmqz_DsNaZ9S1Bw6UbZkDLowuuTCjBWUax0vBMMxdy6XjEEK4Oq9lKMvx9JzjmeJf1knoqSNrox3Ka0rnxXpNAz6sATvme8p9mTXyp0cX4lF4U2J54xa2_S9NF5QWvpXvBeC4GAJx7QaSw4zrUkrc6XyaAiFnLhQEwKJCwUw4NOqIuYvYp_IXhw-5Ti_icDlZS-282PcccnBeOcX7vc21pozibIdmZJKqXNsL1Ibx5Nkx1F1jLnekJAmdaACDjYRLL_6n3W4wUp19UvzB1lGtXcJKLLkqB6YDiZNu16OSiSprfmrRXvYmvD8m6Fnl5aetgKw'}"
                }
            },
            AllowedScopes =
            {
                OidcConstants.StandardScopes.OpenId,
                "apiscope"
            },
            AllowedGrantTypes = 
            {
                OidcConstants.GrantTypes.JwtBearer,
            },
            AccessTokenType = AccessTokenType.Jwt,
            AllowAccessTokensViaBrowser = false,            
            AllowOfflineAccess = false,
            AllowPlainTextPkce = false,
            AlwaysIncludeUserClaimsInIdToken = true,
            AlwaysSendClientClaims = true,
            BackChannelLogoutSessionRequired = true,
            RequireClientSecret = true,            
            RequirePkce = true,
            RequireConsent = false,
            RefreshTokenUsage = TokenUsage.OneTimeOnly,            
        },
    })
    .AddInMemoryApiResources(new []
    {
        new ApiResource()
        {
            Name = "api",
            Scopes = 
            { 
                "apiscope",
            },
            UserClaims =
            {
                "a",
            },
        },
    })
    .AddInMemoryApiScopes(new[]
    {
        new ApiScope()
        {
            Name = "apiscope",
            UserClaims =
            {
                "a",
            }
        }
    })
    .AddInMemoryIdentityResources(new IdentityResource[]
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResources.Email(),
    })
    .AddJwtBearerClientAuthentication()
    .AddExtensionGrantValidator<JwtBearerExtensionGrant>()
    .AddInMemoryPersistedGrants()
    .AddTestUsers(new()
    {
        new TestUser()
        {
            SubjectId = "test@test.test",
            Username = "test@test.test",
            IsActive = true,
            Password = "empty",
            Claims = new[]
            {
                new Claim("a", "a-value"),
            }
        },
    })
    .AddDeveloperSigningCredential();

var app = builder.Build();
app.UseIdentityServer();
app.UseAuthorization();
app.MapGet("/", () => "Hello World!");

app.Run();
