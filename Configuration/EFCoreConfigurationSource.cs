using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace IDP_Testing.Configuration;

public class EFCoreConfigurationSource : IConfigurationSource
{
    private readonly Action<DbContextOptionsBuilder> _optionsAction;

    public EFCoreConfigurationSource(Action<DbContextOptionsBuilder> optionsAction)
    {
        _optionsAction = optionsAction;
    }

    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new EFCoreConfigurationProvider(_optionsAction);
    }
}