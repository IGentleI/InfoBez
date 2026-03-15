using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using RsaLab.Web.Models;
using RsaLab.Web.Services;

namespace RsaLab.Web.Pages;

public class IndexModel(RsaService rsaService) : PageModel
{
    private readonly RsaService _rsaService = rsaService;

    [BindProperty]
    public RsaRequest Input { get; set; } = new()
    {
        PlainText = "Пример текста: RSA 2026, English + русский текст.",
        DigitsInN = 49
    };

    public RsaResult? Result { get; private set; }

    public int? SecurityBits { get; private set; }

    public string? PerformanceSummary { get; private set; }

    public void OnGet()
    {
    }

    public void OnPost()
    {
        if (string.IsNullOrWhiteSpace(Input.PlainText))
        {
            ModelState.AddModelError(string.Empty, "Введите исходный текст.");
            return;
        }

        if (Input.DigitsInN < 6)
        {
            ModelState.AddModelError(string.Empty, "Количество десятичных знаков N должно быть >= 6.");
            return;
        }

        Result = _rsaService.Run(Input);
        SecurityBits = RsaService.EstimateSecurityBits(Result.N);
        PerformanceSummary = $"Генерация ключей: {Result.KeyGenerationTime.TotalMilliseconds:F1} мс, " +
                             $"шифрование: {Result.EncryptionTime.TotalMilliseconds:F1} мс, " +
                             $"дешифрование: {Result.DecryptionTime.TotalMilliseconds:F1} мс.";
    }
}
