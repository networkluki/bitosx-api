using System.Diagnostics;
using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

// Argon2id benchmark for the BitosX account-password hasher on this host.
// Candidate params: m=47104 KiB (46 MiB), t=3, p=1. Measures single-hash latency
// and p50/p95 under concurrency for maxConcurrency in {1,2,3}, honoring the hard
// budget memoryKiB * maxConcurrency <= 192 MiB.

const int MemoryKiB = 19456;
const int Iterations = 3;
const string Password = "benchmark-password-value-1234567890";

static long Median(List<long> xs)
{
    xs.Sort();
    return xs.Count == 0 ? 0 : xs[xs.Count / 2];
}

static long Percentile(List<long> xs, double p)
{
    if (xs.Count == 0) return 0;
    xs.Sort();
    var idx = (int)Math.Ceiling(p / 100.0 * xs.Count) - 1;
    return xs[Math.Clamp(idx, 0, xs.Count - 1)];
}

var core = new KonsciousArgon2Core();

Console.WriteLine($"Host CPUs={Environment.ProcessorCount}  m={MemoryKiB}KiB t={Iterations} p=1");
Console.WriteLine("cap | budgetOK | single(ms) | p50(ms) | p95(ms) | throughput(h/s) | peakWS(MiB)");

foreach (var cap in new[] { 1, 2, 3 })
{
    var budgetOk = (long)MemoryKiB * cap <= 192 * 1024;
    var hasher = new Argon2idPasswordHasher(
        new Argon2ParametersOptions { MemoryKiB = MemoryKiB, Iterations = Iterations, Lanes = 1, MaxConcurrency = cap },
        core);

    // Warm up.
    hasher.Hash(Password);

    // Single-hash latency (no contention), median of 5.
    var single = new List<long>();
    for (var i = 0; i < 5; i++)
    {
        var sw = Stopwatch.StartNew();
        hasher.Hash(Password);
        sw.Stop();
        single.Add(sw.ElapsedMilliseconds);
    }

    // Concurrent load: 24 hashes issued in parallel; the hasher's internal
    // semaphore caps real concurrency at `cap`.
    const int total = 24;
    var latencies = new System.Collections.Concurrent.ConcurrentBag<long>();
    var overall = Stopwatch.StartNew();
    Parallel.For(0, total, _ =>
    {
        var sw = Stopwatch.StartNew();
        hasher.Hash(Password);
        sw.Stop();
        latencies.Add(sw.ElapsedMilliseconds);
    });
    overall.Stop();

    var lat = latencies.ToList();
    var throughput = total / Math.Max(0.001, overall.Elapsed.TotalSeconds);
    var peakWs = Process.GetCurrentProcess().PeakWorkingSet64 / (1024.0 * 1024.0);

    Console.WriteLine($"{cap,3} | {(budgetOk ? "yes" : "NO"),7} | {Median(single),10} | {Percentile(lat, 50),7} | {Percentile(lat, 95),7} | {throughput,15:F2} | {peakWs,10:F0}");
}
