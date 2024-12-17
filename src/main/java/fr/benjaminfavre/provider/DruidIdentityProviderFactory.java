package fr.benjaminfavre.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

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
}
