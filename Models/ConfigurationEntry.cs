namespace IDP_Testing.Models;

public class ConfigurationEntry
{
    public int Id { get; set; }
    public required string Key { get; set; }
    public string? Value { get; set; }
    public DateTime LastModified { get; set; } = DateTime.UtcNow;
}