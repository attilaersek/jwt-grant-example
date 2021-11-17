# jwt-grant-example

```csharp
            const string secp256r1Oid = "1.2.840.10045.3.1.7";  //oid for prime256v1(7)  other identifier: secp256r1v
            var algorithm = ECDsa.Create(ECCurve.CreateFromValue(secp256r1Oid)); // generate asymmetric key pair
            var request = new CertificateRequest("cn=foobar", algorithm, HashAlgorithmName.SHA256);
            var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

            var privateJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(certificate.GetECDsaPrivateKey()));
            privateJwk.Use = "sig"; //signature
            var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(certificate.GetECDsaPublicKey()));
            publicJwk.Use = "sig";
            var privateJwkJson = JsonExtensions.SerializeToJson(privateJwk);
            var publicJwkJson = JsonExtensions.SerializeToJson(publicJwk);
            var jwt = new SecurityTokenDescriptor()
            {
                Issuer = "client",
                Audience = "server",
                SigningCredentials = new SigningCredentials(privateJwk, SecurityAlgorithms.EcdsaSha256Signature),
            };
            var jwtJson = new JsonWebTokenHandler().CreateToken(jwt);
```
