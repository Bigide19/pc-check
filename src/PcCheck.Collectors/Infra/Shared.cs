namespace PcCheck.Collectors.Infra;

// One fetch shared by several collectors in the same scan (e.g. disk info for type and health).
public sealed class Shared<T>(Func<CancellationToken, Task<T>> fetch)
{
    private readonly Lazy<Task<T>> _task = new(() => Task.Run(() => fetch(CancellationToken.None)));

    public Task<T> GetAsync(CancellationToken ct) => _task.Value.WaitAsync(ct);
}
