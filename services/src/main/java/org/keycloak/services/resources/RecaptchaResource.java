package org.keycloak.services.resources;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;
import javax.imageio.ImageIO;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.sessions.StickySessionEncoderProvider;

import net.logicsquad.nanocaptcha.image.ImageCaptcha;

public class RecaptchaResource {

    private final KeycloakSession session;

    public RecaptchaResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response generate() {
        RealmModel realm = session.getContext().getRealm();

        String rawCookie =
                session.getContext().getRequestHeaders().getCookies().get("AUTH_SESSION_ID") !=
                        null ? session.getContext().getRequestHeaders().getCookies().get("AUTH_SESSION_ID").getValue() : null;

        if (rawCookie == null || rawCookie.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing AUTH_SESSION_ID").build();
        }

        StickySessionEncoderProvider routeEncoder =
                session.getProvider(StickySessionEncoderProvider.class);
        var decodedSession = routeEncoder.decodeSessionIdAndRoute(rawCookie);
        String signedPart = decodedSession.sessionId();
        AuthenticationSessionManager manager = new
                AuthenticationSessionManager(session);
        String rootSessionId =
                manager.decodeBase64AndValidateSignature(signedPart);
        if (rootSessionId == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Malformed AUTH_SESSION_ID").build();
        }
        String tabId =
                session.getContext().getUri().getQueryParameters().getFirst("tab_id");

        RootAuthenticationSessionModel rootSession =
                session.authenticationSessions()
                        .getRootAuthenticationSession(realm, rootSessionId);
        if (rootSession == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid root session").build();
        }

        AuthenticationSessionModel authSession =
                rootSession.getAuthenticationSessions().get(tabId);
        if (authSession == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid tab_id").build();
        }

        ImageCaptcha captcha = new ImageCaptcha.Builder(200, 50)
                .addContent(6)
                .addBackground()
                .build();
        String captchaText = captcha.getContent();
        String encodedImage = encodeImage(captcha.getImage());

        authSession.setAuthNote("captcha_expected", captchaText);

        return Response.ok(new CaptchaResponse(encodedImage)).build();
    }

    private String encodeImage(BufferedImage image) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            ImageIO.write(image, "png", output);
            return Base64.getEncoder().encodeToString(output.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CAPTCHA", e);
        }
    }

    public static class CaptchaResponse {
        public String image;
        public CaptchaResponse(String image) {
            this.image = image;
        }
    }
}
