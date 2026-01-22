# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Validates that we have the necessary tools
RUN dotnet --version

# Install Node.js (required for the IDP_Testing.csproj build target we added)
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Copy the solution and project files first (for better caching)
COPY ["IDP_Testing.slnx", "./"]
COPY ["IDP_Testing/IDP_Testing.csproj", "IDP_Testing/"]
COPY ["react-front-end/package.json", "react-front-end/"]
COPY ["react-front-end/package-lock.json", "react-front-end/"]

# Restore dependencies
RUN dotnet restore "IDP_Testing/IDP_Testing.csproj"

# Copy the rest of the source code
COPY . .

# Publish the application
# This will trigger the 'PublishReactFrontend' target in the .csproj,
# which runs 'npm install' and 'npm run build' automatically.
WORKDIR "/src/IDP_Testing"
RUN dotnet publish "IDP_Testing.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Stage 2: Run the application
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
EXPOSE 8080
EXPOSE 8443

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "IDP_Testing.dll"]
