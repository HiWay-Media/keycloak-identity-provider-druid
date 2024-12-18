package media.hiway.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class DruidIdentityProviderFactory extends AbstractIdentityProviderFactory<DruidIdentityProvider> implements SocialIdentityProviderFactory<DruidIdentityProvider> {
    public static final String PROVIDER_ID = "druid";

    @Override
    public String getName() {
        return "Druid";
    }

    @Override
    public DruidIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new DruidIdentityProvider(session, new DruidIdentityProviderConfig(model));
    }

    @Override
    public DruidIdentityProviderConfig createConfig() {
        return new DruidIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("displayName").label("Display name").helpText("Text that is shown on the login page. Defaults to 'Sign in with Druid'").type(ProviderConfigProperty.STRING_TYPE).add()
                //.property().name("teamId").label("Team ID").helpText("Your 10-character Team ID obtained from your Druid developer account.").type(ProviderConfigProperty.STRING_TYPE).add()
                //.property().name("keyId").label("Key ID").helpText("A 10-character key identifier obtained from your Druid developer account.").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name("prodEnv").label("Is Prod").helpText("Is production environment.").type(ProviderConfigProperty.STRING_TYPE).add()
                .build();
    }
}
