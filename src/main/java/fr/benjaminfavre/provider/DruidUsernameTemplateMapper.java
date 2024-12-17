package fr.benjaminfavre.provider;

import org.keycloak.broker.oidc.mappers.UsernameTemplateMapper;

public class DruidUsernameTemplateMapper extends UsernameTemplateMapper {
    private static final String[] cp = new String[] { DruidIdentityProviderFactory.PROVIDER_ID };

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return "druid-username-template-mapper";
    }
}
