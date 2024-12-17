Druid Social Identity Provider
This project is a Druid Social Identity Provider for Keycloak. It allows Keycloak to integrate with Druid for authentication and user management.

Installation
Clone the repository:
```bash
git clone <repository-url>
```

Navigate to the project directory:
```bash
cd druid-social-identity-provider
```

Build the project using Maven:
```bash
mvn clean package
```

Usage
-- Deploy the generated JAR file (druid-social-identity-provider-1.0.3.jar) to your Keycloak server.
-- Configure the Druid Identity Provider in the Keycloak admin console:
--- Go to the Identity Providers section.
--- Add a new provider and select "Druid" from the list.
--- Fill in the required configuration fields such as keyId and teamId.

Configuration
The configuration for the Druid Identity Provider can be found in the following files:
-- realm-identity-provider-apple-ext.html
-- admin-messages_en.properties