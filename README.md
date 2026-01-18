# IDP Testing Application

A Blazor Server application demonstrating multiple authentication protocols: **OpenID Connect (OIDC)**, **SAML 2.0**, and **WS-Federation**.

## Features

- **Three authentication methods** running simultaneously
- **Keycloak** for OIDC and SAML 2.0 (runs in Docker)
- **Azure AD** for WS-Federation testing (free tier)
- **Configuration management** UI for runtime config changes
- **Database-backed configuration** overrides

---

## Quick Start

### 1. Prerequisites

- .NET 10 SDK
- Docker Desktop
- Visual Studio 2022+ (or VS Code)
- Azure AD account (free - optional, only for WS-Fed testing)

### 2. Start Keycloak

Keycloak runs at: http://localhost:8080 (admin/admin)

### 3. Configure User Secrets

**Right-click** the `IDP_Testing` project → **"Manage User Secrets"**

Add this configuration:

```json
{
  "Keycloak": {
    "Authority": "http://localhost:8080/realms/your-realm",
    "Audience": "your-audience",
    "ClientId": "blazor-app",
    "ClientSecret": "your-client-secret",
    "ResponseType": "code",
    "Scope": "openid profile email"
  },
  "SAML": {
    "SPOptions": {
      "EntityID": "http://localhost:5000/Saml2",
      "ReturnURL": "http://localhost:5000/signin-saml",
      "Certificate": {
        "File": "saml2.pfx",
        "Password": "your-pfx-password"
      }
    },
    "IdentityProviders": [
      {
        "EntityId": "http://localhost:8080/realms/your-realm",
        "MetadataLocation": "http://localhost:8080/realms/your-realm/protocols/saml/metadata",
        "AllowUnsolicitedAuthnResponse": true
      }
    ]
  }
}
```

For example, with Personal Access Token (PAT) Authorization:
Invoke-RestMethod -X POST -H "Authorization: Bearer {PAT}" -H "Content-Type: application/json" -d "
{
  'Keycloak': {
    'Authority': 'http://localhost:8080/realms/your-realm',
    'Audience': 'your-audience',
    'ClientId': 'blazor-app',
    'ClientSecret': 'your-client-secret',
    'ResponseType': 'code',
    'Scope': 'openid profile email'
  },
  'SAML': {
    'SPOptions': {
      'EntityID': 'http://localhost:5000/Saml2',
      'ReturnURL': 'http://localhost:5000/signin-saml',
      'Certificate': {
        'File': 'saml2.pfx',
        'Password': 'your-pfx-password'
      }
    },
    'IdentityProviders': [
      {
        'EntityId': 'http://localhost:8080/realms/your-realm',
        'MetadataLocation': 'http://localhost:8080/realms/your-realm/protocols/saml/metadata',
        'AllowUnsolicitedAuthnResponse': true
      }
    ]
  }
}" http://localhost:5000/config

**Note:** Replace the placeholders (`your-realm`, `your-audience`, `your-client-secret`, `saml2.pfx`, `your-pfx-password`) with your actual values.

**Getting Keycloak Client Secret:**
1. Open http://localhost:8080
2. Login: `admin` / `admin`
3. Go to: Clients → `blazor-app` → Credentials tab
4. Copy the **Client Secret**

**Getting Azure AD Tenant ID (Optional - for WS-Fed):**
1. Go to https://portal.azure.com
2. Navigate to: Microsoft Entra ID → Overview
3. Copy the **Directory (tenant) ID**
4. Replace `YOUR-TENANT-ID` in the user secrets above

### 4. Run the Application

Or press **F5** in Visual Studio.

Navigate to: https://localhost:7235

---

## Azure AD Setup (Optional - WS-Fed Only)

### Create App Registration

1. Go to https://portal.azure.com
2. Navigate to: **Microsoft Entra ID** → **App registrations** → **New registration**
3. Configure:
   - **Name**: `Blazor IDP Testing`
   - **Account type**: `Single tenant`
   - **Redirect URI**: `Web` → `https://localhost:7235/signin-wsfed`
4. After registration:
   - Go to **Authentication** → Add **Front-channel logout URL**: `https://localhost:7235/signout-wsfed`
   - Copy the **Directory (tenant) ID** from Overview tab
5. Add tenant ID to your user secrets (as shown above)

**Cost:** Free forever (Azure AD Free tier)

---

## Authentication Methods

| Method | Provider | Port | Test Credentials |
|--------|----------|------|------------------|
| **OIDC** | Keycloak | 8080 | Configured in Keycloak |
| **SAML 2.0** | Keycloak | 8080 | Configured in Keycloak |
| **WS-Fed** | Azure AD | N/A | Your Azure AD account |

---

## Configuration Management

Access the admin panel at: https://localhost:7235/admin/configuration

**Requires:** `app-admin` role

Features:
- View active configuration
- Create database configuration overrides
- Search and filter settings
- Reload configuration at runtime

---

## Project Structure

---

## Security

✅ **Secrets are stored in User Secrets** - Never committed to Git  
✅ **Base configuration is public** - No sensitive data in `appsettings.json`  
✅ **Production ready** - Use Azure Key Vault or environment variables for deployment

**User Secrets Location:**  
`%APPDATA%\Microsoft\UserSecrets\997056bc-add4-45a7-941e-d792936b22b5\secrets.json`

---

## Database

The app uses **SQL Server LocalDB** to store configuration overrides.

**Create/Update Database:**

**Connection String:** Configured in `appsettings.json` (uses integrated auth)

---

## Troubleshooting

### "No such host is known" Error
- **Cause:** WS-Fed configuration is empty or invalid
- **Fix:** Either remove WS-Fed config from user secrets, or add valid Azure AD tenant ID

### "Client secret is required"
- **Cause:** Missing Keycloak client secret in user secrets
- **Fix:** Right-click project → Manage User Secrets → Add Keycloak:ClientSecret

### Changes to secrets.json not applying
- **Fix:** Restart the application after modifying user secrets

---

## License

MIT License - See LICENSE file for details
