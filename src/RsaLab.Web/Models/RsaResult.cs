using System.Numerics;

namespace RsaLab.Web.Models;

public class RsaResult
{
    public required BigInteger P { get; init; }
    public required BigInteger Q { get; init; }
    public required BigInteger N { get; init; }
    public required BigInteger Phi { get; init; }
    public required BigInteger E { get; init; }
    public required BigInteger D { get; init; }
    public required int BlockSizeBytes { get; init; }
    public required IReadOnlyList<BigInteger> CipherBlocks { get; init; }
    public required string DecryptedText { get; init; }
    public required TimeSpan KeyGenerationTime { get; init; }
    public required TimeSpan EncryptionTime { get; init; }
    public required TimeSpan DecryptionTime { get; init; }

    public string CipherAsText => string.Join(" ", CipherBlocks.Select(c => c.ToString()));
}
