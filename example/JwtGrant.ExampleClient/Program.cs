using IdentityModel;
using IdentityModel.Client;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

const string rsaKey = "{'d':'GmiaucNIzdvsEzGjZjd43SDToy1pz-Ph-shsOUXXh-dsYNGftITGerp8bO1iryXh_zUEo8oDK3r1y4klTonQ6bLsWw4ogjLPmL3yiqsoSjJa1G2Ymh_RY_sFZLLXAcrmpbzdWIAkgkHSZTaliL6g57vA7gxvd8L4s82wgGer_JmURI0ECbaCg98JVS0Srtf9GeTRHoX4foLWKc1Vq6NHthzqRMLZe-aRBNU9IMvXNd7kCcIbHCM3GTD_8cFj135nBPP2HOgC_ZXI1txsEf-djqJj8W5vaM7ViKU28IDv1gZGH3CatoysYx6jv1XJVvb2PH8RbFKbJmeyUm3Wvo-rgQ','dp':'YNjVBTCIwZD65WCht5ve06vnBLP_Po1NtL_4lkholmPzJ5jbLYBU8f5foNp8DVJBdFQW7wcLmx85-NC5Pl1ZeyA-Ecbw4fDraa5Z4wUKlF0LT6VV79rfOF19y8kwf6MigyrDqMLcH_CRnRGg5NfDsijlZXffINGuxg6wWzhiqqE','dq':'LfMDQbvTFNngkZjKkN2CBh5_MBG6Yrmfy4kWA8IC2HQqID5FtreiY2MTAwoDcoINfh3S5CItpuq94tlB2t-VUv8wunhbngHiB5xUprwGAAnwJ3DL39D2m43i_3YP-UO1TgZQUAOh7Jrd4foatpatTvBtY3F1DrCrUKE5Kkn770M','e':'AQAB','kid':'ZzAjSnraU3bkWGnnAqLapYGpTyNfLbjbzgAPbbW2GEA','kty':'RSA','n':'wWwQFtSzeRjjerpEM5Rmqz_DsNaZ9S1Bw6UbZkDLowuuTCjBWUax0vBMMxdy6XjEEK4Oq9lKMvx9JzjmeJf1knoqSNrox3Ka0rnxXpNAz6sATvme8p9mTXyp0cX4lF4U2J54xa2_S9NF5QWvpXvBeC4GAJx7QaSw4zrUkrc6XyaAiFnLhQEwKJCwUw4NOqIuYvYp_IXhw-5Ti_icDlZS-282PcccnBeOcX7vc21pozibIdmZJKqXNsL1Ibx5Nkx1F1jLnekJAmdaACDjYRLL_6n3W4wUp19UvzB1lGtXcJKLLkqB6YDiZNu16OSiSprfmrRXvYmvD8m6Fnl5aetgKw','p':'7enorp9Pm9XSHaCvQyENcvdU99WCPbnp8vc0KnY_0g9UdX4ZDH07JwKu6DQEwfmUA1qspC-e_KFWTl3x0-I2eJRnHjLOoLrTjrVSBRhBMGEH5PvtZTTThnIY2LReH-6EhceGvcsJ_MhNDUEZLykiH1OnKhmRuvSdhi8oiETqtPE','q':'0CBLGi_kRPLqI8yfVkpBbA9zkCAshgrWWn9hsq6a7Zl2LcLaLBRUxH0q1jWnXgeJh9o5v8sYGXwhbrmuypw7kJ0uA3OgEzSsNvX5Ay3R9sNel-3Mqm8Me5OfWWvmTEBOci8RwHstdR-7b9ZT13jk-dsZI7OlV_uBja1ny9Nz9ts','qi':'pG6J4dcUDrDndMxa-ee1yG4KjZqqyCQcmPAfqklI2LmnpRIjcK78scclvpboI3JQyg6RCEKVMwAhVtQM6cBcIO3JrHgqeYDblp5wXHjto70HVW6Z8kBruNx1AH9E8LzNvSRL-JVTFzBkJuNgzKQfD0G77tQRgJ-Ri7qu3_9o1M4'}";

var jwk = new JsonWebKey(rsaKey);
var response = await RequestTokenAsync(new SigningCredentials(jwk, "RS256"));
var status = response switch 
{
    { IsError: true , ErrorType: ResponseErrorType.Http } => $"{response.HttpStatusCode}: {response.Error}",
    { IsError: true } => $"{response.Raw}",
    _ => $"{response.Json}\n{new JwtSecurityTokenHandler().ReadToken(response.AccessToken) as JwtSecurityToken}",
};
Console.WriteLine(status);
if(!response.IsError)
{
    var userInfoResponse = await GetUserInfoAsync(response.AccessToken);
    Console.WriteLine(userInfoResponse.Raw);
}
Console.ReadLine();

static async Task<UserInfoResponse> GetUserInfoAsync(string accessToken)
{
    var client = new HttpClient(new HttpClientHandler()
    {
        ServerCertificateCustomValidationCallback =
            (httpRequestMessage, cert, cetChain, policyErrors) =>
            {
                return true;
            }
    });
    var discoveryDocument = await client.GetDiscoveryDocumentAsync("https://localhost:7172");

    var response = await client.GetUserInfoAsync(new UserInfoRequest()
    {
        Address = discoveryDocument.UserInfoEndpoint,
        Token = accessToken        
    });

    return response;
}

static async Task<TokenResponse> RequestTokenAsync(SigningCredentials credential)
{
    var client = new HttpClient(new HttpClientHandler()
    {
        ServerCertificateCustomValidationCallback = 
            (httpRequestMessage, cert, cetChain, policyErrors) =>
            {
                return true;
            }
    });
    var discoveryDocument = await client.GetDiscoveryDocumentAsync("https://localhost:7172");

    const string clientId = "client.jwt";
    var response = await client.RequestTokenAsync(new()
    {
        Address = discoveryDocument.TokenEndpoint,
        GrantType = OidcConstants.GrantTypes.JwtBearer,
        ClientId = clientId,
        ClientSecret = "secret",
        Parameters = new()
        {
            { "scope", "openid apiscope"},
            { "assertion", CreateAssertionToken(credential, clientId, discoveryDocument.TokenEndpoint) },
        },
    });

    return response;
}

static string CreateAssertionToken(SigningCredentials credential, string clientId, string audience)
{
    var now = DateTime.UtcNow;

    var token = new JwtSecurityToken(
        clientId,
        audience,
        new Claim[]
        {
            new(JwtClaimTypes.JwtId, Guid.NewGuid().ToString()),
            new(JwtClaimTypes.Issuer, clientId),
            new(JwtClaimTypes.Subject, "test@test.test"),
            new(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64),
        },
        now,
        now.AddMinutes(3),
        credential
    );

    var tokenHandler = new JwtSecurityTokenHandler();
    return tokenHandler.WriteToken(token);
}