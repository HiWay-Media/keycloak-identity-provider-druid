package media.hiway.provider;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public class DruidIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    private String userJson;
    public static final String OAUTH2_PARAMETER_CODE = "code";

    private static final Logger logger              = Logger.getLogger(DruidIdentityProvider.class);
    private static final String AUTH_URL            = "https://auth.test.id.sevillafc.es/oauth2/authorize";
    private static final String TOKEN_URL           = "https://auth.test.id.sevillafc.es/oauth2/token";
    private static final String JWKS_URL            = "https://auth.test.id.sevillafc.es/oauth2/keys";
    private static final String ISSUER              = "https://auth.test.id.sevillafc.es";
    //
    private static final String AUTH_URL_TEST       = "https://auth.test.id.sevillafc.es/oauth2/authorize";
    private static final String TOKEN_URL_TEST      = "https://auth.test.id.sevillafc.es/oauth2/token";
    private static final String JWKS_URL_TEST       = "https://auth.test.id.sevillafc.es/oauth2/keys";
    private static final String ISSUER_TEST         = "https://auth.test.id.sevillafc.es";
    static final String DRUID_AUTHZ_CODE            = "druid-authz-code";


    public DruidIdentityProvider(KeycloakSession session, DruidIdentityProviderConfig config) {
        super(session, config);
        String defaultScope = config.getDefaultScope(); 
        //
        logger.debugf("defaultScope ", defaultScope);
        //
        config.setAuthorizationUrl("https://auth.test.id.sevillafc.es/oauth2/authorize");
        config.setTokenUrl("https://auth.test.id.sevillafc.es/oauth2/token");
        
        // check if inside the config exist openid likes scope=openid+email+name, if yes remove it 
        if (defaultScope.contains(SCOPE_OPENID)) {
            config.setDefaultScope("");
        }
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        //return new DruidIdentityProviderEndpoint(this, realm, callback, event, session);
        return new OIDCEndpoint(callback, realm, event);
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext context = super.getFederatedIdentity(response);

        if (userJson != null) {
            try {
                User user = JsonSerialization.readValue(userJson, User.class);
                context.setEmail(user.email);
                context.setFirstName(user.name.firstName);
                context.setLastName(user.name.lastName);
            } catch (IOException e) {
                logger.errorf("Failed to parse userJson [%s]: %s", userJson, e);
            }
        }

        return context;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        DruidIdentityProviderConfig config = (DruidIdentityProviderConfig) getConfig();
        tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId());
        String base64PrivateKey = config.getClientSecret();

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] pkc8ePrivateKey = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkc8ePrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm(Algorithm.ES256);
            keyWrapper.setKid(config.getKeyId());
            keyWrapper.setPrivateKey(privateKey);
            SignatureSignerContext signer = new ServerECDSASignatureSignerContext(keyWrapper);

            long currentTime = Time.currentTime();
            JsonWebToken token = new JsonWebToken();
            token.issuer(config.getTeamId());
            token.iat(currentTime);
            token.exp(currentTime + 15 * 60);
            token.audience("https://sevillafc.ott.es");
            token.subject(config.getClientId());
            String clientSecret = new JWSBuilder().jsonContent(token).sign(signer);

            tokenRequest.param(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.errorf("Failed to generate client secret: %s", e);
        }

        return tokenRequest;
    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }


    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);

        final DruidIdentityProviderConfig config = (DruidIdentityProviderConfig) getConfig();
        //
        uriBuilder.queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
            .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
            .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId())
            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        return uriBuilder;
    }

    protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event, DruidIdentityProvider.this);
        }

        @POST
        public Response authResponse(
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                @FormParam("user") String userJson,
                @FormParam(OAuth2Constants.ERROR) String error) {
            DruidIdentityProvider.this.userJson = userJson;
            return super.authResponse(state, authorizationCode, error, error);
        }
    }



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
