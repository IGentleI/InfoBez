namespace RsaLab.Web.Models;

public class RsaRequest
{
    public string PlainText { get; set; } = string.Empty;
    public int DigitsInN { get; set; } = 49;
}
