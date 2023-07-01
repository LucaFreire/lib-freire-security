namespace security_jwt.JwtService;

using security_jwt.PasswordProvider;
using System.Text.Json;
using System.Text;
using System;
using System.Security.Cryptography;

public class JwtService : IJwtService
{
    IPasswordProvider provider;
    public JwtService(IPasswordProvider provider)
        => this.provider = provider;

    public string GetToken<T>(T obj)
    {
        var json = JsonSerializer.Serialize(obj);

        var header = getJsonHeader();
        var payload = this.jsonToBase64(json);
        var signature = this.getSignature(header, payload);

        return $"{header}.{payload}.{signature}";
    }

    public T Validate<T>(string jwt)
        where T : class
    {
        string[] parts = jwt.Split(".");

        string header = parts[0];
        string payload = parts[1];
        string signature = parts[2];

        string newSignature = this.getSignature(header, payload);

        if (newSignature != signature)
            throw new ArgumentException("Invalid signature.");

        var data = Base64toJson(payload);
        var returnData = JsonSerializer.Deserialize<T>(data);

        return returnData;
    }

    private string Base64toJson(string base64)
    {
        var paddingBase64 = addPadding(base64);
        byte[] bytes = Convert.FromBase64String(paddingBase64);
        var json = Encoding.UTF8.GetString(bytes);
        return json;
    }
  
    private string addPadding(string base64)
    {
        int bits = 6 * base64.Length;
        while (bits % 8 != 0)
        {
            bits += 6;
            base64 += "=";
        }
        return base64;

    }
   
    private string getSignature(string header, string payload)
    {
        var password = this.provider.ProvidePassword();
        var data = header + payload + password;
        var signature = this.applyHash(data);
        return signature;
    }

    private string applyHash(string str)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(str);
        var hashBytes = sha.ComputeHash(bytes);
        var hash = Convert.ToBase64String(hashBytes);
        var unpadHash = this.removePadding(hash);
        return unpadHash;
    }
   
    private string getJsonHeader()
    {
        string header = """
            {
                "alg": "HS256",
                "typ": "JWT"
            }
            """;
        var base64 = this.jsonToBase64(header);
        return base64;
    }
   
    private string jsonToBase64(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var base64 = Convert.ToBase64String(bytes);
        var unpadBase64 = this.removePadding(base64);
        return unpadBase64;
    }
    
    private string removePadding(string base64)
    {
        var unpaddingBase64 = base64.Replace("=", "");
        return unpaddingBase64;
    }
}