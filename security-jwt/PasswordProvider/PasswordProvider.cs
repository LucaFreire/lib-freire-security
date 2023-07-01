namespace security_jwt.PasswordProvider;

public class PasswordProvider : IPasswordProvider
{
    string password;
    public PasswordProvider(string password) 
        => this.password = password;
        
    public string ProvidePassword()
    => this.password;
}