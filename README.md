# Keycloak Druid Social Identity Provider

This repository contains an extension for Keycloak to authenticate users through DruID, leveraging DruID's identity management capabilities.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features

- Integrates DruID as an external identity provider in Keycloak.
- Supports authentication and role mapping.
- Synchronizes user attributes from DruID to Keycloak.

## Prerequisites

- A running instance of [Keycloak](https://www.keycloak.org/).
- Developer access to a DruID account to configure API keys and endpoints.
- Java 11 or later.
- Apache Maven for building the project.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/HiWay-Media/keycloak-identity-provider-drui.git
   cd keycloak-identity-provider-drui
   ```

2. **Build the Project:**

   Ensure Maven is installed, then run:

   ```bash
   mvn clean package
   ```

   This command compiles the project and packages it into a JAR file located in the `target` directory.

3. **Deploy the Extension:**

   Copy the JAR file to the Keycloak deployments directory, typically `$KEYCLOAK_HOME/standalone/deployments/`.

   ```bash
   cp target/keycloak-identity-provider-drui.jar $KEYCLOAK_HOME/standalone/deployments/
   ```

4. **Restart Keycloak:**

   Restart your Keycloak server to apply the changes.

## Configuration

1. **Set Up DruID:**

   - Log into your DruID account to create and configure an OAuth application.
   - Record the client ID, client secret, and relevant endpoint URLs.

2. **Configure Keycloak:**

   - Access the Keycloak Admin Console.
   - In your realm, navigate to **Identity Providers** and click on **Add provider**.
   - Select **DruID** from the list and fill in the provider details:
     - Client ID
     - Client Secret
     - Authorization URL
     - Token URL
     - User Info URL

3. **Mapping Roles and Attributes:**

   - Define required roles in Keycloak and map them to DruID roles.
   - Configure attribute mappings to ensure DruID attributes map correctly to Keycloak user attributes.

## Usage

Once configured, users can log into applications secured by Keycloak using their DruID credentials. The integration will handle user authentication and synchronization of roles and attributes.

## Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create a branch for your feature or bug fix.
3. Commit your changes and open a pull request with a detailed description.

Ensure all contributions are tested and documented.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Support

For support or inquiries, please open an issue in this repository or contact HiWay Media through [our support page](https://hiway.media/support).