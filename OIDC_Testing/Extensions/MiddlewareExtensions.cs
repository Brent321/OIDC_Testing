namespace OIDC_Testing.Extensions;

public static class MiddlewareExtensions
{
    public static IApplicationBuilder UseCustomStatusCodePages(this IApplicationBuilder app)
    {
        return app.UseStatusCodePages(context =>
        {
            var statusCode = context.HttpContext.Response.StatusCode;
            if (statusCode == StatusCodes.Status403Forbidden)
            {
                context.HttpContext.Response.Redirect("/forbidden");
            }
            else if (statusCode == StatusCodes.Status404NotFound)
            {
                context.HttpContext.Response.Redirect("/not-found");
            }

            return Task.CompletedTask;
        });
    }
}