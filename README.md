# IDP Testing Platform

A modern **Hybrid .NET 10** application combining **Blazor Server**, **React 19**, and a robust **Authentication** system (OIDC, SAML, WS-Fed). This project demonstrates a "Backend for Frontend" (BFF) architecture with dynamic plugin loading and deep Keycloak integration.

## Key Features

### Hybrid Architecture (BFF)
- **.NET 10 Backend**: Serves both API endpoints and Blazor Server components.
- **React 19 Frontend**: Integrated SPA hosted at `/react`.
- **YARP Reverse Proxy**: Seamless development experience with React Hot Reload (Vite) proxied through the .NET host.
- **Unified Auth**: Both Blazor and React share the same secure HttpOnly authentication cookies.

### Multi-Protocol Authentication
- **OpenID Connect (OIDC)**: Integrated with Keycloak.
- **SAML 2.0**: Service Provider (SP) support.
- **WS-Federation**: Legacy support scenarios.
- **Keycloak Docker**: Pre-configured Identity Provider with automatic realm import.

### Runtime Plugin System
- **Hot-Plug Blazor**: Upload `.dll` files at runtime via the Admin Dashboard.
- **Dynamic Routing**: New pages in uploaded assemblies are automatically discovered and routable.
- **Isolation**: Plugins are loaded into the application context without restarting the server.

### Dynamic Configuration
- **Database-Backed Config**: Configurations (Authentication settings, toggles) are stored in SQL Server and override `appsettings.json`.
- **Admin UI**: Modify system behavior at runtime without deployments.

---

## Prerequisites

- **.NET 10 SDK** (Preview)
- **Node.js 22+** (For React/Vite)
- **Docker Desktop** (For Keycloak & SQL Server)
- **Visual Studio 2022** (Preview) or **VS Code**

---

## Quick Start

### 1. Infrastructure Setup
Start the required services (Keycloak & SQL Server) using Docker Compose:

```bash
docker-compose up -d
```
*   **Keycloak** will start at `http://localhost:8080` (Admin: `admin`/`admin`).
*   It automatically imports the `blazor-dev` realm with pre-configured clients and users.

### 2. Frontend Setup
Install the dependencies for the React application:

```bash
cd react-front-end
npm install
cd ..
```

### 3. Run the Application
You can run the application directly from Visual Studio or the CLI.

```bash
cd IDP_Testing
dotnet run
```

*   The application will start at `https://localhost:7235`.
*   **Background Service**: The app automatically detects if you are in development and starts the Vite Dev Server (`npm run dev`) for you.
*   **YARP Proxy**: Requests to `/react/*` are transparently proxied to the live Vite server (Hot Reload enabled).

---

## Usage

### Default Routes
- **Home**: `https://localhost:7235/` (Blazor Homepage)
- **React App**: `https://localhost:7235/react` (React SPA)
- **Admin**: `https://localhost:7235/admin` (Requires `app-admin` role)

### Login Credentials (Keycloak)
- **Admin User**: `bob` / `Pass123$` (Example admin)
- **Standard User**: `alice` / `Pass123$`

### Managing Plugins
1.  Log in as **Bob** (Admin).
2.  Navigate to **Admin Dashboard** -> **Plugin Management**.
3.  Upload a Blazor `.dll` (e.g., `TestBlazorPlugin.dll`).
4.  The new components (e.g., `/plugin-test`) effectively become part of the running application immediately.

---

## Deployment & Production

### Frontend Build
The project is configured to automatically build the React frontend when publishing in Release mode.

```xml
<!-- IDP_Testing.csproj -->
<Target Name="BuildReactApp" BeforeTargets="Build" Condition=" '$(Configuration)' == 'Release' ">
    <Exec Command="npm run build" WorkingDirectory="../react-front-end" />
</Target>
```

### Configuration Toggle
You can simulate production behavior (serving static bundled files instead of Hot Reload) in development by modifying `appsettings.json`:

```json
"React": {
  "UseDevelopmentServer": false
}
```

### Docker
A production-ready `Dockerfile` is included in the root.

```bash
docker build -t idp-testing .
docker run -p 8080:8080 idp-testing
```

---

## Project Structure

```
├── IDP_Testing/              # .NET 10 ASP.NET Core Project
│   ├── Components/           # Blazor Server Components
│   ├── Controllers/          # API & Auth Controllers
│   ├── Extensions/           # YARP & Service Configurations
│   ├── Plugins/              # Runtime uploaded plugin folder
│   ├── Services/             # Application Logic
│   └── wwwroot/              # Static Assets (React build in prod)
├── react-front-end/          # React 19 + Vite Project
├── TestBlazorPlugin/         # Sample Runtime Plugin (RCL)
└── docker-compose.yml        # Infrastructure (Keycloak, MSSQL)
```
