package com.vunetsystems.captcha;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;

@Path("/regen-captcha")
public class CaptchaResource{
    private final KeycloakSession session;
    private final CaptchaService service = new CaptchaService();

    public CaptchaResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCaptcha() {
        String text = service.generateText();
        String image = service.generateImage(text);
        session.getContext().getAuthenticationSession().setAuthNote("captcha_expected", text);
        return Response.ok(new CaptchaResponse(image)).build();
    }

    public static class CaptchaResponse {
        public String image;
        public CaptchaResponse(String image) { this.image = image; }
    }
}