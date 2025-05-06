package media.hiway.provider;

import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

public class DruidIdentityProviderFactory extends AbstractIdentityProviderFactory<DruidIdentityProvider> implements SocialIdentityProviderFactory<DruidIdentityProvider> {
    public static final String PROVIDER_ID = "druid";
    private static final Logger logger              = Logger.getLogger(DruidIdentityProviderFactory.class);

    @Override
    public String getName() {
        return "Druid";
    }

    @Override
    public DruidIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        logger.infof("Creating DruidIdentityProvider create() session: %s, model: %s", session, model);
        return new DruidIdentityProvider(session, new DruidIdentityProviderConfig(model));
    }

    @Override
    public DruidIdentityProviderConfig createConfig() {
        logger.infof("Creating DruidIdentityProviderConfig createConfig()");
        return new DruidIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        logger.infof("Creating DruidIdentityProviderConfig getConfigProperties()");
        List<ProviderConfigProperty> configProperties = new ArrayList<>(super.getConfigProperties());

        ProviderConfigProperty frontendErrorUrl = new ProviderConfigProperty();
        frontendErrorUrl.setName("frontendErrorUrl");
        frontendErrorUrl.setLabel("Frontend Error Redirect URL");
        frontendErrorUrl.setHelpText("URL to redirect users to when Druid login fails or is cancelled.");
        frontendErrorUrl.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(frontendErrorUrl);

        ProviderConfigProperty displayName = new ProviderConfigProperty();
        displayName.setName("displayName");
        displayName.setLabel("Display Name");
        displayName.setHelpText("Text that is shown on the login page. Defaults to 'Sign in with Druid'");
        displayName.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(displayName);
        
        return configProperties;
    }
}
