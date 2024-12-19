package media.hiway.provider;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.validation.Validation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.core.UriBuilder;

public class DruidIdentityProvider extends AbstractOAuth2IdentityProvider<DruidIdentityProviderConfig> implements SocialIdentityProvider<DruidIdentityProviderConfig> {
    private String userJson;
    public static final String OAUTH2_PARAMETER_CODE = "code";

    private static final Logger logger              = Logger.getLogger(DruidIdentityProvider.class);
    // private static final String AUTH_URL            = "https://auth.id.sevillafc.es/oauth2/authorize";
    // private static final String TOKEN_URL           = "https://auth.id.sevillafc.es/oauth2/token";
    // private static final String JWKS_URL            = "https://auth.id.sevillafc.es/oauth2/keys";
    // private static final String ISSUER              = "https://auth.id.sevillafc.es";
    //
    private static final String AUTH_URL_TEST       = "https://auth.test.id.sevillafc.es/oauth2/authorize";
    private static final String TOKEN_URL_TEST      = "https://auth.test.id.sevillafc.es/oauth2/token";
    private static final String PROFILE_URL         = "https://graph.test.id.sevillafc.es/activityid/v1/user/userinfo";
    // private static final String JWKS_URL_TEST       = "https://auth.test.id.sevillafc.es/oauth2/keys";
    // private static final String ISSUER_TEST         = "https://auth.test.id.sevillafc.es";
    static final String DRUID_AUTHZ_CODE            = "druid-authz-code";
    // private final DruidIdentityProviderConfig config;

    public DruidIdentityProvider(KeycloakSession session, DruidIdentityProviderConfig config) {
        super(session, config);
        logger.infof("DruidIdentityProvider config: %v, session: %v ", config, session);
        //String defaultScope = config.getDefaultScope();
        String isProd = config.getProd();
        //this.config = config;
        logger.infof("isProd ", isProd);
        // this.config = config;
        // logger.infof("config ", config);
        //
        config.setAuthorizationUrl(AUTH_URL_TEST);
        config.setTokenUrl(TOKEN_URL_TEST);
        config.setUserInfoUrl(PROFILE_URL);
        config.setDefaultScope("");
        // check if inside the config exist openid likes scope=openid+email+name, if yes remove it 
        // if (defaultScope.contains(SCOPE_OPENID)) {
        //     config.setDefaultScope("");
        // }
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }


    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    // @Override
    // public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    //     //return new DruidIdentityProviderEndpoint(this, realm, callback, event, session);
    //     return new OIDCEndpoint(callback, realm, event);
    // }
    
    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        logger.infof("getFederatedIdentity before response: %s", response);
        // parse the response string into json
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonResponse;
        try {
            jsonResponse = mapper.readTree(response);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not parse response from Druid", e);
        }
        logger.infof("getFederatedIdentity jsonResponse: %s", jsonResponse);
        logger.infof("getFederatedIdentity jsonResponse.get(\"access_token\"): %s", jsonResponse.get("access_token"));

        BrokeredIdentityContext context = doGetFederatedIdentity(jsonResponse.get("access_token").asText());
        logger.infof("getFederatedIdentity response: %s and context: %s", response, context);

        return context;
    }


    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        logger.infof("doGetFederatedIdentity before accessToken: %s", accessToken);
        try {
            logger.infof("doGetFederatedIdentity before SimpleHttp.doGet", "Authorization Bearer " + accessToken);
            JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
            logger.infof("doGetFederatedIdentity JsonNode profile response: %s", profile);
            if (profile.has("error") && !profile.get("error").isNull()) {
                throw new IdentityBrokerException("Error in Druid Graph API response. Payload: " + profile.toString());
            }
            return extractIdentityFromProfile(null, profile);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from Druid Graph", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String id = getJsonProperty(profile, "sub");
        logger.infof("extractIdentityFromProfile before id: %s", id);
        try {
            logger.infof("extractIdentityFromProfile config ", getConfig());
            BrokeredIdentityContext user = new BrokeredIdentityContext(id, getConfig());
            logger.infof("extractIdentityFromProfile user: %s", user);
            String email = getJsonProperty(profile, "email");
            if (email == null && profile.has("userPrincipalName")) {
                String username = getJsonProperty(profile, "userPrincipalName");
                if (Validation.isEmailValid(username)) {
                    email = username;
                }
            }
            user.setUsername(email != null ? email : id);
            user.setFirstName(getJsonProperty(profile, "name"));
            user.setLastName(getJsonProperty(profile, "family_name"));
            if (email != null)
                user.setEmail(email);
            user.setIdp(this);

            AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from Druid Graph", e);
        }
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        logger.infof("SimpleHTTP", tokenRequest);        
        return super.authenticateTokenRequest(tokenRequest);
    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }


    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        final DruidIdentityProviderConfig config = (DruidIdentityProviderConfig) getConfig();
        logger.infof("createAuthorizationUrl config: %s", config);
        //
        uriBuilder.queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
            .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
            .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId())
            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        return uriBuilder;
    }

    // protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
    //     public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
    //         super(callback, realm, event, DruidIdentityProvider.this);
    //     }

    //     @POST
    //     @Override
    //     public Response authResponse(
    //             @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
    //             @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
    //             @FormParam("user") String userJson,
    //             @FormParam(OAuth2Constants.ERROR) String error) {
    //         //
    //         logger.infof("authResponse state: %s | userJson %s", state, userJson);
    //         DruidIdentityProvider.this.userJson = userJson;
    //         return super.authResponse(state, authorizationCode, error, error);
    //     }
    // }



    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class User {
        public String email;
        public Name name;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Name {
            public String firstName;
            public String lastName;
        }
    }
}
