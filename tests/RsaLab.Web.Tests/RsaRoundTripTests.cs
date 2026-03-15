using RsaLab.Web.Models;
using RsaLab.Web.Services;

namespace RsaLab.Web.Tests;

public class RsaRoundTripTests
{
    private readonly RsaService _service = new();

    [Theory]
    [InlineData("sample01.txt")]
    [InlineData("sample02.txt")]
    [InlineData("sample03.txt")]
    [InlineData("sample04.txt")]
    [InlineData("sample05.txt")]
    [InlineData("sample06.txt")]
    [InlineData("sample07.txt")]
    [InlineData("sample08.txt")]
    [InlineData("sample09.txt")]
    [InlineData("sample10.txt")]
    public void EncryptDecrypt_ReturnsOriginalText(string fileName)
    {
        var text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-data", fileName));

        var result = _service.Run(new RsaRequest
        {
            PlainText = text,
            DigitsInN = 49
        });

        Assert.Equal(text, result.DecryptedText);
        Assert.NotEmpty(result.CipherBlocks);
        Assert.Equal(49, result.N.ToString().Length);
    }
}
