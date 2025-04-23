package media.hiway.authenticator;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;


public class DruidErrorHandlerAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DruidErrorHandlerAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String error = session.getAuthNote("IDENTITY_PROVIDER_ERROR");
        
        if (error != null) {
            logger.infof("Detected IDENTITY_PROVIDER_ERROR: %s", error);

            String frontendUrl = context.getAuthenticatorConfig()
                        .getConfig()
                        .get("frontendErrorUrl");

            if (frontendUrl == null || frontendUrl.isEmpty()) {
                logger.info("frontendErrorUrl is not configured, using default URL.");
                frontendUrl = "https://sevillafc.hiwaymedia.io/";
            } else {
                logger.infof("Using configured frontendErrorUrl: %s", frontendUrl);
            }

            URI redirectUri = URI.create(frontendUrl + "?error=" + URLEncoder.encode(error, StandardCharsets.UTF_8));
            logger.infof("Redirecting to: ", redirectUri);

            Response response = Response.status(302)
                .location(redirectUri)
                .build();

            context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, response);
        } else {
            logger.info("No IDENTITY_PROVIDER_ERROR detected, proceeding with success.");
            context.success();
        }
    }


    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Set the required actions for the user after authentication
    }

    @Override
    public void close() {
        // Closes any open resources
    }
}


