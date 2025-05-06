package media.hiway.provider;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

public final class DruidIdentityProvider extends AbstractOAuth2IdentityProvider<DruidIdentityProviderConfig> implements SocialIdentityProvider<DruidIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(DruidIdentityProvider.class);

    private static final String BROKER_CODE_CHALLENGE_PARAM = "BROKER_CODE_CHALLENGE";

    public DruidIdentityProvider(KeycloakSession session, DruidIdentityProviderConfig config) {
        super(session, config);
        logger.infof("DruidIdentityProvider Config.AUTH_URL: %s | Config.TOKEN_URL: %s", Config.AUTH_URL, Config.TOKEN_URL);
        
        config.setAuthorizationUrl(Config.AUTH_URL);
        config.setTokenUrl(Config.TOKEN_URL);
        config.setUserInfoUrl(Config.PROFILE_URL);
        config.setDefaultScope("");
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return Config.PROFILE_URL;
    }


    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }
    
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
            JsonNode profile = SimpleHttp.doGet(Config.PROFILE_URL, session).header("Authorization", "Bearer " + accessToken).asJson();
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
            final DruidIdentityProviderConfig config = (DruidIdentityProviderConfig) getConfig();
            logger.infof("extractIdentityFromProfile config %v, id %s", config, id);
            BrokeredIdentityContext user = new BrokeredIdentityContext(id);
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

            AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, config.getAlias());
            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from Druid Graph", e);
        }
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        logger.infof("SimpleHTTP: %s", tokenRequest);        
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

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        logger.debugf("callback realm: %s, callback: %s, event: %s", realm, callback, event);
        // Use our local Endpoint class rather than the default Keycloak endpoint.
        return new Endpoint(session, callback, event, this);
    }

    protected static class Endpoint {
        protected final RealmModel realm;
        protected final AuthenticationCallback callback;
        protected final EventBuilder event;
        private final DruidIdentityProvider provider;

        protected final KeycloakSession session;

        protected final ClientConnection clientConnection;

        protected final HttpHeaders headers;

        public Endpoint(KeycloakSession session, AuthenticationCallback callback, EventBuilder event, DruidIdentityProvider provider) {
            this.session = session;
            this.realm = session.getContext().getRealm();
            this.clientConnection = session.getContext().getConnection();
            this.callback = callback;
            this.event = event;
            this.provider = provider;
            this.headers = session.getContext().getRequestHeaders();
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            
            logger.infof("authResponse state: %s, authorizationCode: %s, error: %s", state, authorizationCode, error);
            if (state == null) {
                logger.infof("errorIdentityProviderLogin: %s", Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }
            logger.infof("state: %s", state);
            try {
                logger.infof("state: %s", state);
                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
                session.getContext().setAuthenticationSession(authSession);

                DruidIdentityProviderConfig providerConfig = provider.getConfig();
                
                logger.infof("error: %s", error);
                if (error != null) {
                    logger.error(error + " for broker login " + providerConfig.getProviderId());
                    logger.infof("error.equals('user_cancel') %v", error.equals("user_cancel"));
                    if (error.equals(ACCESS_DENIED)) {
                        logger.info("OAuthErrorException.AccessDenied");
                        return callback.cancelled(providerConfig);
                    }else if (error.equals("user_cancel")){
                        logger.info("OAuthErrorException.UserCancel");
                        // redirect to the frontend error URL
                        // String frontendErrorUrl = providerConfig.getConfig().get("frontendErrorUrl");
                        String frontendErrorUrl = providerConfig.getFrontendErrorUrl();
                        if (frontendErrorUrl != null && !frontendErrorUrl.isEmpty()) {
                            return Response.status(Response.Status.FOUND)
                                    .location(UriBuilder.fromUri(frontendErrorUrl).build())
                                    .build();
                        } else {
                            return callback.cancelled(providerConfig);
                        }
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        logger.info("OAuthErrorException.LoginRequired || OAuthErrorException.InteractionRequired");
                        return callback.error(error);
                    } else {
                        logger.info("OAuthErrorException.UnexpectedError");
                        return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }
                logger.infof("authorizationCode: %s", authorizationCode);
                if (authorizationCode != null) {
                    logger.infof("authorizationCode: %s", authorizationCode);
                    String response = generateTokenRequest(authorizationCode).asString();

                    BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);

                    if (providerConfig.isStoreToken()) {
                        // make sure that token wasn't already set by getFederatedIdentity();
                        // want to be able to allow provider to set the token itself.
                        if (federatedIdentity.getToken() == null)federatedIdentity.setToken(response);
                    }

                    federatedIdentity.setIdpConfig(providerConfig);
                    federatedIdentity.setIdp(provider);
                    federatedIdentity.setAuthenticationSession(authSession);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                logger.infof("e.getResponse() %s", e.getResponse());
                return e.getResponse();
            } catch (IdentityBrokerException e) {
                logger.infof("errorIdentityProviderLogin: %s", e.getMessage());
                if (e.getMessageCode() != null) {
                    return errorIdentityProviderLogin(e.getMessageCode());
                }
                logger.error("Failed to make identity provider oauth callback", e);
            } catch (Exception e) {
                logger.infof("errorIdentityProviderLogin: %s", Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                logger.error("Failed to make identity provider oauth callback", e);
            }
            logger.infof("errorIdentityProviderLogin: %s", Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        private Response errorIdentityProviderLogin(String message) {
            logger.infof("errorIdentityProviderLogin: %s", message);
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode) {
            KeycloakContext context = session.getContext();
            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();
            SimpleHttp tokenRequest = SimpleHttp.doPost(providerConfig.getTokenUrl(), session)
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(OAUTH2_PARAMETER_REDIRECT_URI, Urls.identityProviderAuthnResponse(context.getUri().getBaseUri(),
                            providerConfig.getAlias(), context.getRealm().getName()).toString())
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

            if (providerConfig.isPkceEnabled()) {

                // reconstruct the original code verifier that was used to generate the code challenge from the HttpRequest.
                String stateParam = session.getContext().getUri().getQueryParameters().getFirst(OAuth2Constants.STATE);
                if (stateParam == null) {
                    logger.warn("Cannot lookup PKCE code_verifier: state param is missing.");
                    return tokenRequest;
                }

                RealmModel realm = context.getRealm();
                IdentityBrokerState idpBrokerState = IdentityBrokerState.encoded(stateParam, realm);
                ClientModel client = realm.getClientByClientId(idpBrokerState.getClientId());

                AuthenticationSessionModel authSession = ClientSessionCode.getClientSession(
                        idpBrokerState.getEncoded(),
                        idpBrokerState.getTabId(),
                        session,
                        realm,
                        client,
                        event,
                        AuthenticationSessionModel.class);

                if (authSession == null) {
                    logger.warnf("Cannot lookup PKCE code_verifier: authSession not found. state=%s", stateParam);
                    return tokenRequest;
                }

                String brokerCodeChallenge = authSession.getClientNote(BROKER_CODE_CHALLENGE_PARAM);
                if (brokerCodeChallenge == null) {
                    logger.warnf("Cannot lookup PKCE code_verifier: brokerCodeChallenge not found. state=%s", stateParam);
                    return tokenRequest;
                }

                tokenRequest.param(OAuth2Constants.CODE_VERIFIER, brokerCodeChallenge);
            }

            return provider.authenticateTokenRequest(tokenRequest);
        }
    }
}