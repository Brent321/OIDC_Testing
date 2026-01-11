using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace IDP_Testing.Configuration;

public static class EFCoreConfigurationExtensions
{
    public static IConfigurationBuilder AddEFCoreConfiguration(
        this IConfigurationBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        return builder.Add(new EFCoreConfigurationSource(optionsAction));
    }
}