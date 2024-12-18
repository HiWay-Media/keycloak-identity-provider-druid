package media.hiway.provider;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import static media.hiway.provider.DruidIdentityProvider.OAUTH2_PARAMETER_CODE;

public class DruidIdenityProviderEndpoint {

    protected static final Logger logger = Logger.getLogger(DruidIdenityProviderEndpoint.class);

    private static final String OAUTH2_PARAMETER_STATE = "state";
    private static final String OAUTH2_PARAMETER_USER = "user";
    private static final String ACCESS_DENIED = "access_denied";
    private static final String USER_CANCELLED_AUTHORIZE = "user_cancelled_authorize";

    private final DruidIdentityProvider druidIdentityProvider;
    private final RealmModel realm;
    private final IdentityProvider.AuthenticationCallback callback;
    private final EventBuilder event;

    protected KeycloakSession session;


    public DruidIdenityProviderEndpoint(DruidIdentityProvider druidIdentityProvider, RealmModel realm, IdentityProvider.AuthenticationCallback callback, EventBuilder event, KeycloakSession session) {
        this.druidIdentityProvider = druidIdentityProvider;
        this.realm = realm;
        this.callback = callback;
        this.event = event;
        this.session = session;
    }

    @POST
    public Response authResponse(@FormParam(OAUTH2_PARAMETER_STATE) String state, @FormParam(OAUTH2_PARAMETER_CODE) String authorizationCode, @FormParam(OAUTH2_PARAMETER_USER) String user, @FormParam(OAuth2Constants.ERROR) String error) {
        if (state == null) {
            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
        }
        // TODO
        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    private Response errorIdentityProviderLogin(String message) {
        return errorIdentityProviderLogin(message, Response.Status.BAD_GATEWAY);
    }

    private Response errorIdentityProviderLogin(String message, Response.Status status) {
        sendErrorEvent();
        return ErrorPage.error(session, null, status, message);
    }

    private void sendErrorEvent() {
        event.event(EventType.IDENTITY_PROVIDER_LOGIN);
        event.detail("idp", druidIdentityProvider.getConfig().getProviderId());
        event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
    }
}
