package media.hiway.provider;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

class DruidIdentityProviderConfig extends OIDCIdentityProviderConfig {
    DruidIdentityProviderConfig() {}

    DruidIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }
    private static final String PROD_ENV = "prodEnv";
    private static final String DISPLAY_ICON_CLASSES = "fa fa-dragon";
    private static final String DISPLAY_NAME = "displayName";
    private static final String DEFAULT_DISPLAY_NAME = "Sign in with Druid";
    // need to setup if is debug or prod urls
     public String getProd() {
        return getConfig().get(PROD_ENV);
    }

    public void setProd(String isProd) {
        getConfig().put(PROD_ENV, isProd);
    }


    /*public String getKeyId() {
        return getConfig().get("keyId");
    }

    public String getTeamId() {
        return getConfig().get("teamId");
    }*/

    @Override
    public void setDisplayName(String displayName) {
        getConfig().put(DISPLAY_NAME, displayName);
    }

    @Override
    public String getDisplayName() {
        var displayName = getConfig().get(DISPLAY_NAME);
        if (displayName == null || displayName.isBlank()) {
            return DEFAULT_DISPLAY_NAME;
        }
        return displayName;
    }

    @Override
    public String getDisplayIconClasses() {
        return DISPLAY_ICON_CLASSES;
    }
}
