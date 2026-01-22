using IDP_Testing.Services;
using Yarp.ReverseProxy.Configuration;

namespace IDP_Testing.Extensions;

public static class YarpExtensions
{
    public static IServiceCollection AddReactDevelopmentProxy(this IServiceCollection services, IHostEnvironment environment, IConfiguration configuration)
    {
        var useDevServer = configuration.GetValue<bool>("React:UseDevelopmentServer", true);

        if (environment.IsDevelopment() && useDevServer)
        {
            services.AddReverseProxy()
            .LoadFromMemory(
                [
                    new RouteConfig
                    {
                        RouteId = "react-route",
                        // Catch-all route for any path starting with /react
                        ClusterId = "react-cluster",
                        Match = new RouteMatch
                        {
                            Path = "/react/{**catch-all}"
                        }
                    }
                ],
                [
                    new ClusterConfig
                    {
                        ClusterId = "react-cluster",
                        Destinations = new Dictionary<string, DestinationConfig>
                        {
                            { "vite-server", new DestinationConfig { Address = "http://localhost:5173" } }
                        }
                    }
                ]
            );

            // Start the React Dev Server automatically
            services.AddHostedService<ReactDevelopmentServer>();
        }

        return services;
    }
}
