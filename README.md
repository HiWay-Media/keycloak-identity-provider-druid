# Keycloak Identity Provider for Druid (ActivityID)

A Keycloak **Social Identity Provider** that brokers authentication against the
Druid / ActivityID OAuth2 platform (e.g. `auth.id.sevillafc.es`). It plugs into
Keycloak's identity-brokering flow so that users can sign in with their Druid
account and be federated as Keycloak users.

The plugin also ships a custom **Authenticator** (`DruidErrorHandlerAuthenticator`)
that intercepts identity-provider errors and redirects the browser to a
configurable frontend URL — useful when you want the SPA to render the error
instead of the default Keycloak error page.

---

## Features

- OAuth2 Authorization-Code flow against Druid (`/oauth2/authorize` + `/oauth2/token`).
- User profile fetched from the Druid Graph (`/activityid/v1/user/userinfo`).
- PKCE support (inherited from Keycloak's `AbstractOAuth2IdentityProvider`).
- Configurable display name on the Keycloak login page (default: *"Sign in with Druid"*).
- Configurable **frontend error URL** for cancelled / failed logins.
- Username-template mapper compatible with the `druid` provider id.
- Custom error-handling authenticator that turns broker errors into a 302 to your frontend.
- Two build profiles (**dev** / **prod**) that bake the right Druid endpoint URLs into the jar.

---

## Architecture

```
Browser ──▶ Keycloak ──▶ Druid (auth.id.sevillafc.es)
                │
                ├── DruidIdentityProvider          (OAuth2 broker, callback, userinfo)
                ├── DruidIdentityProviderFactory   (registers provider id "druid")
                ├── DruidIdentityProviderConfig    (config keys: displayName, frontendErrorUrl, prodEnv)
                ├── DruidUsernameTemplateMapper    (idp mapper bound to "druid")
                ├── Config                         (loads /config/config.properties at class-init)
                └── DruidErrorHandlerAuthenticator (post-IdP step, redirects on error)
```

### Source layout

| Path | Purpose |
|------|---------|
| [src/main/java/media/hiway/provider/DruidIdentityProvider.java](src/main/java/media/hiway/provider/DruidIdentityProvider.java) | OAuth2 broker. Builds the authorization URL, exchanges the code for a token, fetches user info, maps it to a `BrokeredIdentityContext`. Also handles `error=user_cancel` by redirecting to `frontendErrorUrl`. |
| [src/main/java/media/hiway/provider/DruidIdentityProviderFactory.java](src/main/java/media/hiway/provider/DruidIdentityProviderFactory.java) | Registers the provider under the id `druid` and declares the admin-UI config properties (`frontendErrorUrl`, `displayName`). |
| [src/main/java/media/hiway/provider/DruidIdentityProviderConfig.java](src/main/java/media/hiway/provider/DruidIdentityProviderConfig.java) | Typed accessors over the IdP config map (`displayName`, `frontendErrorUrl`, `prodEnv`). Sets the FontAwesome icon class `fa fa-dragon`. |
| [src/main/java/media/hiway/provider/Config.java](src/main/java/media/hiway/provider/Config.java) | Loads `config/config.properties` from the classpath at class-init and exposes `AUTH_URL`, `TOKEN_URL`, `PROFILE_URL` as `static final`. |
| [src/main/java/media/hiway/provider/DruidUsernameTemplateMapper.java](src/main/java/media/hiway/provider/DruidUsernameTemplateMapper.java) | Subclass of Keycloak's `UsernameTemplateMapper` declared compatible with the `druid` provider id. |
| [src/main/java/media/hiway/authenticator/DruidErrorHandlerAuthenticator.java](src/main/java/media/hiway/authenticator/DruidErrorHandlerAuthenticator.java) | Authenticator that reads the auth-session note `IDENTITY_PROVIDER_ERROR` and redirects (302) to a configurable frontend URL with `?error=…`. |
| [src/main/java/media/hiway/authenticator/DruidErrorHandlerAuthenticatorFactory.java](src/main/java/media/hiway/authenticator/DruidErrorHandlerAuthenticatorFactory.java) | Factory for the authenticator above (`PROVIDER_ID = "druid-error-handler"`). |
| [src/main/resources/META-INF/services/](src/main/resources/META-INF/services/) | SPI service files registering the factories with Keycloak. |
| [src/main/resources/META-INF/jboss-deployment-structure.xml](src/main/resources/META-INF/jboss-deployment-structure.xml) | Declares Keycloak module dependencies for WildFly classloading. |
| [src/main/resources/theme-resources/messages/admin-messages_en.properties](src/main/resources/theme-resources/messages/admin-messages_en.properties) | Translations for the admin UI (`druid.*` keys). |
| [src/main/resources/theme-resources/resources/partials/realm-identity-provider-druid-ext.html](src/main/resources/theme-resources/resources/partials/realm-identity-provider-druid-ext.html) | Extra Angular partial rendered in the IdP edit page (extra config inputs). |
| [config-dev.properties](config-dev.properties) / [config-prod.properties](config-prod.properties) | Environment-specific Druid endpoints, packaged into the jar by the Gradle build. |

---

## Druid endpoints

| Variable | Dev | Prod |
|----------|-----|------|
| `auth.url`    | `https://auth.test.id.sevillafc.es/oauth2/authorize` | `https://auth.id.sevillafc.es/oauth2/authorize` |
| `token.url`   | `https://auth.test.id.sevillafc.es/oauth2/token` | `https://auth.id.sevillafc.es/oauth2/token` |
| `profile.url` | `https://graph.test.id.sevillafc.es/activityid/v1/user/userinfo` | `https://graph.id.sevillafc.es/activityid/v1/user/userinfo` |

These URLs are read once at class-load by [Config.java](src/main/java/media/hiway/provider/Config.java)
from `config/config.properties` on the classpath. The Gradle build (see below) bundles
the right `config-*.properties` file under that name and path into the produced jar.

---

## Build

The project ships **both** a Maven `pom.xml` and a Gradle `build.gradle`. The
Gradle build is the one that produces the dev/prod-flavored jars used in
deployment; Maven is kept around for compatibility.

### Gradle (recommended)

```bash
# Production jar -> build/libs/druid-social-identity-provider-prod-<version>.jar
./gradlew clean buildProd

# Development jar -> build/libs/druid-social-identity-provider-dev-<version>.jar
./gradlew clean buildDev
```

The two tasks differ only in which `config-*.properties` is copied into the jar
under `config/config.properties`. Current version is declared in [build.gradle](build.gradle).

### Maven (legacy)

```bash
mvn clean package
```

Produces a single `druid-social-identity-provider-<version>.jar` without the
embedded environment config — if you go this route, you must put a
`config/config.properties` on the Keycloak classpath yourself.

---

## Installation in Keycloak

1. Copy the jar into Keycloak's provider directory:

   ```bash
   cp build/libs/druid-social-identity-provider-prod-*.jar \
      $KEYCLOAK_HOME/providers/
   ```

2. Rebuild and restart Keycloak (Quarkus distribution):

   ```bash
   $KEYCLOAK_HOME/bin/kc.sh build
   $KEYCLOAK_HOME/bin/kc.sh start
   ```

3. In the admin console:
   - **Identity Providers ▸ Add provider… ▸ Druid**
   - Fill in **Client ID** and **Client Secret** issued by Druid.
   - (Optional) **Display Name** — text shown on the login page; defaults to *"Sign in with Druid"*.
   - (Optional) **Frontend Error Redirect URL** — where the browser is sent if the user cancels or Druid returns an error.
   - Save.

The provider appears with a dragon icon (`fa fa-dragon`) on the login screen.

---

## Configuration reference

### Identity Provider config

Set on the IdP itself (admin UI ▸ Identity Providers ▸ Druid):

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `clientId`         | string  | yes | OAuth2 client id issued by Druid. |
| `clientSecret`     | string  | yes | OAuth2 client secret issued by Druid. |
| `displayName`      | string  | no  | Label on the login button. Defaults to *"Sign in with Druid"*. |
| `frontendErrorUrl` | string  | no  | Browser is 302-redirected here on `error=user_cancel`. If unset, the standard Keycloak `cancelled` flow is used. |
| `prodEnv`          | string  | no  | Free-form flag exposed via the admin UI partial — currently informational only. |

The Druid endpoints (`auth.url`, `token.url`, `profile.url`) are **not** configurable
from the admin UI; they are baked into the jar at build time via `config-dev.properties`
or `config-prod.properties`.

### Error-handler authenticator config

`DruidErrorHandlerAuthenticator` is a separate SPI registered as
`druid-error-handler`. To use it:

1. Edit your **Browser** authentication flow (or copy it).
2. Add an execution **"Druid Error Handler"** after the *Identity Provider Redirector*.
3. Open its config and set **Frontend Error URL** to the SPA URL that should
   render the error.

When Keycloak puts an `IDENTITY_PROVIDER_ERROR` note on the auth session, this
authenticator builds `<frontendErrorUrl>?error=<urlencoded message>` and returns
a 302 to the browser.

> ⚠️ If the URL is not configured the authenticator falls back to a hardcoded
> `https://sevillafc.hiwaymedia.io/`. Configure it explicitly for any other
> deployment — see [DruidErrorHandlerAuthenticator.java:38](src/main/java/media/hiway/authenticator/DruidErrorHandlerAuthenticator.java#L38).

---

## How the broker flow works

1. User clicks *Sign in with Druid* in Keycloak.
2. `DruidIdentityProvider.createAuthorizationUrl` builds
   `${auth.url}?response_type=code&client_id=…&redirect_uri=…&state=…` and the
   browser is redirected to Druid.
3. Druid authenticates the user and redirects back to Keycloak's broker
   endpoint.
4. The inner `Endpoint.authResponse` handler:
   - validates `state` and binds the auth session,
   - on `error=access_denied` → calls `callback.cancelled(...)`,
   - on `error=user_cancel` → 302s to `frontendErrorUrl` (if set), otherwise
     `cancelled(...)`,
   - on `error=login_required|interaction_required` → propagates via
     `callback.error(...)`,
   - otherwise exchanges `code` at `${token.url}` (with PKCE if enabled),
   - calls `${profile.url}` with `Authorization: Bearer …` and maps the JSON
     into a `BrokeredIdentityContext`.
5. User-attribute mapping uses standard Keycloak JSON attribute mappers; the
   raw profile is stored on the context via `AbstractJsonUserAttributeMapper.storeUserProfileForMapper`.

### Profile → user mapping

| Keycloak field | Source JSON path |
|----------------|------------------|
| id / external id | `sub` |
| username | `email` (or `userPrincipalName` if it is a valid email, else `sub`) |
| email | `email` |
| firstName | `name` |
| lastName | `family_name` |

---

## Development notes

- Java **11** source/target.
- Keycloak target: **22.0.1** for the Gradle build (`build.gradle`); the legacy
  Maven build pins **11.0.2** — prefer Gradle.
- Keycloak deps are `compileOnly` so the jar stays slim and uses the runtime
  modules listed in [jboss-deployment-structure.xml](src/main/resources/META-INF/jboss-deployment-structure.xml).
- Logs are intentionally verbose (`logger.infof(...)` in the broker) — useful
  while integrating with a new Druid tenant; consider reducing log levels in
  production.
- The `frontendErrorUrl` admin partial is in
  [realm-identity-provider-druid-ext.html](src/main/resources/theme-resources/resources/partials/realm-identity-provider-druid-ext.html);
  the legacy `keyId`/`teamId` Apple-style fields are commented out and can be
  removed once nothing else references them.

---

## Versioning

- Gradle artifact: `media.hiway:druid-social-identity-provider:1.1.0` (see [build.gradle](build.gradle)).
- Maven artifact: `fr.benjaminfavre:druid-social-identity-provider:1.0.3` (see [pom.xml](pom.xml)).

The Maven coordinates are inherited from the project's original fork and are
not actively published; treat the Gradle artifact as the source of truth.

---

## License

See [LICENSE](LICENSE).
