package media.hiway.provider;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class DruidIdentityProviderConfig extends OIDCIdentityProviderConfig {
    DruidIdentityProviderConfig() {}

    DruidIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public String getKeyId() {
        return getConfig().get("keyId");
    }

    public String getTeamId() {
        return getConfig().get("teamId");
    }
}
