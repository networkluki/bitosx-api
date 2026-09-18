using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>Fail-closed validation of the always-active Argon2 admission configuration.</summary>
public sealed class Argon2AdmissionOptionsTests
{
    [Fact]
    public void Defaults_AreValid()
    {
        var o = new Argon2AdmissionOptions();
        o.Validate(); // does not throw
        Assert.Equal(2, o.MaxConcurrent);
        Assert.Equal(4, o.QueueCapacity);
        Assert.Equal(2000, o.AcquireTimeoutMilliseconds);
    }

    [Fact] public void ZeroMaxConcurrent_Throws() => Assert.Throws<InvalidOperationException>(() => new Argon2AdmissionOptions { MaxConcurrent = 0 }.Validate());
    [Fact] public void NegativeQueueCapacity_Throws() => Assert.Throws<InvalidOperationException>(() => new Argon2AdmissionOptions { QueueCapacity = -1 }.Validate());
    [Fact] public void ZeroTimeout_Throws() => Assert.Throws<InvalidOperationException>(() => new Argon2AdmissionOptions { AcquireTimeoutMilliseconds = 0 }.Validate());

    [Fact] public void ZeroQueueCapacity_IsAllowed() => new Argon2AdmissionOptions { QueueCapacity = 0 }.Validate(); // no waiting queue is valid
}
