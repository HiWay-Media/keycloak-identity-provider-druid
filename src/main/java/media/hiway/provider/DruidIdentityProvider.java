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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.core.UriBuilder;

public class DruidIdentityProvider extends AbstractOAuth2IdentityProvider<DruidIdentityProviderConfig>
		implements SocialIdentityProvider<DruidIdentityProviderConfig> {

	private static final Logger logger = Logger.getLogger(DruidIdentityProvider.class);

	public DruidIdentityProvider(KeycloakSession session, DruidIdentityProviderConfig config) {
		super(session, config);
		logger.infof("DruidIdentityProvider Config.AUTH_URL: %s | Config.TOKEN_URL: %s", Config.AUTH_URL,
				Config.TOKEN_URL);
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
			JsonNode profile = SimpleHttp.doGet(Config.PROFILE_URL, session)
					.header("Authorization", "Bearer " + accessToken).asJson();
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
		logger.infof("createAuthorizationUrl request %s %s", request.getHttpRequest(), request.getHttpRequest());
		logger.infof("request %v", request.getHttpRequest());
        //logger.infof("getFormParameters %s %s", request.getHttpRequest().getFormParameters().getFirst("x_method") , request.getHttpRequest().getFormParameters().getFirst("x_method") );
        String redirectUri = request.getRedirectUri();
        logger.infof("redirectUri %s", redirectUri);

		// debug logger
		String xMethod = request.getHttpRequest().getDecodedFormParameters().getFirst("x_method");
		String scope = request.getHttpRequest().getDecodedFormParameters().getFirst("scope");
		logger.infof("request x_method: %s", xMethod);
		logger.infof("request scope %s", scope);

		uriBuilder.queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
				.queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
				// take x_method from the http request
				// .queryParam("x_method", request.getHttpRequest().getDecodedFormParameters().get("x_method"))
				// take scope from the http request
				// .queryParam("scope", request.getHttpRequest().getDecodedFormParameters().get("scope"))
				.queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId())
				.queryParam(OAUTH2_PARAMETER_REDIRECT_URI, redirectUri);
		return uriBuilder;
	}

}
