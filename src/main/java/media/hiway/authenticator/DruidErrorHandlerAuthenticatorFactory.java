package media.hiway.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DruidErrorHandlerAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "druid-error-handler";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty frontendUrlProp = new ProviderConfigProperty();
        frontendUrlProp.setName("frontendErrorUrl");
        frontendUrlProp.setLabel("Frontend Error URL");
        frontendUrlProp.setHelpText("The URL to redirect to in case of an authentication error.");
        frontendUrlProp.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(frontendUrlProp);
    }

    @Override
    public String getDisplayType() {
        return "Druid Error Handler";
    }

    @Override
    public String getReferenceCategory() {
        return "Druid Error Handler";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DruidErrorHandlerAuthenticator();
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "This authenticator handles errors during the authentication process and redirects to a specified URL.";
    }
}
