using System.Management;

namespace PcCheck.Collectors.Infra;

public interface IWmi
{
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string wql);
}

public sealed class WmiClient : IWmi
{
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql));
        using var results = searcher.Get();
        var list = new List<IReadOnlyDictionary<string, object?>>();
        foreach (var mo in results)
        {
            using (mo)
            {
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in mo.Properties) row[p.Name] = p.Value;
                list.Add(row);
            }
        }
        return list;
    }
}
