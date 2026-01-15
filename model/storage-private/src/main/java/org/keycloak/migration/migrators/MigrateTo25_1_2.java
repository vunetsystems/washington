package org.keycloak.migration.migrators;

import org.jboss.logging.Logger;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class MigrateTo25_1_2 implements Migration {
    public static final ModelVersion VERSION = new ModelVersion("25.1.2");
    private static final Logger LOG = Logger.getLogger(MigrateTo25_1_2.class);

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

    @Override
    public void migrate(KeycloakSession session) {
        if (session.sessions() != null) {
            session.sessions().migrate(VERSION.toString());
        }
        session.realms().getRealmsStream().forEach(realm -> migrateRealm(session, realm));
    }

    @Override
    public void migrateImport(KeycloakSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateRealm(session, realm);
    }

    protected void migrateRealm(KeycloakSession session, RealmModel realm) {
        if (realm.getName().equals("master")) {
            LOG.infof("Skipping realm: %s", realm.getName());
            return;
        }

        try {
            // CRITICAL FIX: Bind realm to session context BEFORE any operations
            // This must be the FIRST thing we do to avoid "Session not bound to a realm" errors
            session.getContext().setRealm(realm);

            // Check what already exists to avoid duplicate work
            ClientModel existingClient = realm.getClientByClientId("omniagent-client");
            UserModel existingServiceAccount = null;

            try {
                existingServiceAccount = session.users().getUserByUsername(realm, "service-account-omniagent-client");
            } catch (Exception e) {
                LOG.debugf("Could not check for existing service account: %s", e.getMessage());
            }

            // If everything exists, skip migration
            if (existingClient != null && existingServiceAccount != null) {
                LOG.infof("✅ Client and service account already exist in realm '%s'. Migration complete.", realm.getName());
                return;
            }

            // If only service account is missing, create it
            if (existingClient != null && existingServiceAccount == null) {
                LOG.infof("Client exists but service account missing in realm '%s'. Creating service account only.", realm.getName());
                addServiceAccountUser(session, realm);
                LOG.infof("✅ Service account created for realm '%s'", realm.getName());
                return;
            }

            // Perform full migration if client doesn't exist
            LOG.infof("Starting full migration for realm '%s'", realm.getName());

            addBasicClientScope(realm);
            addOmniagentClient(session, realm);
            addServiceAccountUser(session, realm);

            LOG.infof("✅ Successfully completed omniagent-client migration for realm '%s'", realm.getName());
        } catch (Exception e) {
            LOG.errorf(e, "❌ Failed to migrate omniagent-client in realm '%s'", realm.getName());
            // Don't propagate exception - allow Keycloak to continue starting
        }
    }

    private void addBasicClientScope(RealmModel realm) {
        try {
            ClientScopeModel basicScope = KeycloakModelUtils.getClientScopeByName(realm, "basic");
            if (basicScope != null) {
                LOG.infof("Client scope 'basic' already exists in realm '%s'. Skipping.", realm.getName());
                return;
            }

            LOG.infof("Adding 'basic' client scope to realm '%s'", realm.getName());
            basicScope = realm.addClientScope("basic");
            basicScope.setDescription("Basic client scope");
            basicScope.setProtocol("openid-connect");
            basicScope.setAttribute("include.in.token.scope", "false");
            basicScope.setAttribute("display.on.consent.screen", "false");

            LOG.infof("Successfully added 'basic' client scope to realm '%s'", realm.getName());
        } catch (Exception e) {
            LOG.warnf(e, "Failed to add 'basic' client scope in realm '%s'. Continuing...", realm.getName());
        }
    }

    private void addOmniagentClient(KeycloakSession session, RealmModel realm) {
        try {
            ClientModel omniagentClient = realm.getClientByClientId("omniagent-client");
            if (omniagentClient != null) {
                LOG.infof("Client 'omniagent-client' already exists in realm '%s'. Skipping.", realm.getName());
                return;
            }

            LOG.infof("Adding 'omniagent-client' to realm '%s'", realm.getName());
            omniagentClient = realm.addClient("omniagent-client");
            omniagentClient.setName("Omniagent Client");
            omniagentClient.setDescription("Client used by Cairo for communicating with omni-agent");
            omniagentClient.setEnabled(true);
            omniagentClient.setAlwaysDisplayInConsole(true);
            omniagentClient.setClientAuthenticatorType("client-secret");
            omniagentClient.setSecret("ziLtSVdrERLmjG9OYGDsgnDDYKrPx4vG");
            omniagentClient.setPublicClient(false);
            omniagentClient.setStandardFlowEnabled(true);
            omniagentClient.setImplicitFlowEnabled(false);
            omniagentClient.setDirectAccessGrantsEnabled(true);
            omniagentClient.setServiceAccountsEnabled(true);
            omniagentClient.setBearerOnly(false);
            omniagentClient.setConsentRequired(false);
            omniagentClient.setFrontchannelLogout(true);
            omniagentClient.setProtocol("openid-connect");
            omniagentClient.setFullScopeAllowed(true);
            omniagentClient.setNodeReRegistrationTimeout(-1);

            // Add redirect URIs and web origins
            omniagentClient.addRedirectUri("/*");
            omniagentClient.setWebOrigins(Set.of("/*"));

            // Set client attributes
            setClientAttributes(omniagentClient);

            // Add protocol mappers
            addProtocolMappers(omniagentClient);

            // Add client scopes
            addClientScopes(realm, omniagentClient);

            // Add client roles
            addClientRoles(omniagentClient);

            // Enable authorization services
            enableAuthorizationServices(session, omniagentClient);

            LOG.infof("Successfully added 'omniagent-client' to realm '%s'", realm.getName());
        } catch (Exception e) {
            LOG.errorf(e, "Failed to add 'omniagent-client' in realm '%s'", realm.getName());
            throw e; // Re-throw to be caught by parent try-catch
        }
    }

    private void setClientAttributes(ClientModel client) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("client.secret.creation.time", "1684205042");
        attributes.put("client.introspection.response.allow.jwt.claim.enabled", "false");
        attributes.put("post.logout.redirect.uris", "+");
        attributes.put("oauth2.device.authorization.grant.enabled", "false");
        attributes.put("use.jwks.url", "false");
        attributes.put("backchannel.logout.revoke.offline.tokens", "false");
        attributes.put("use.refresh.tokens", "true");
        attributes.put("realm_client", "false");
        attributes.put("oidc.ciba.grant.enabled", "false");
        attributes.put("client.use.lightweight.access.token.enabled", "false");
        attributes.put("backchannel.logout.session.required", "true");
        attributes.put("client_credentials.use_refresh_token", "false");
        attributes.put("tls.client.certificate.bound.access.tokens", "false");
        attributes.put("require.pushed.authorization.requests", "false");
        attributes.put("acr.loa.map", "{}");
        attributes.put("display.on.consent.screen", "false");
        attributes.put("token.response.type.bearer.lower-case", "false");

        attributes.forEach(client::setAttribute);
    }

    private void addProtocolMappers(ClientModel client) {
        addClientIpAddressMapper(client);
        addClientHostMapper(client);
        addClientIdMapper(client);
    }

    private void addClientIpAddressMapper(ClientModel client) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName("Client IP Address");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usersessionmodel-note-mapper");

        Map<String, String> config = new HashMap<>();
        config.put("user.session.note", "clientAddress");
        config.put("id.token.claim", "true");
        config.put("introspection.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("claim.name", "clientAddress");
        config.put("jsonType.label", "String");
        mapper.setConfig(config);

        client.addProtocolMapper(mapper);
    }

    private void addClientHostMapper(ClientModel client) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName("Client Host");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usersessionmodel-note-mapper");

        Map<String, String> config = new HashMap<>();
        config.put("user.session.note", "clientHost");
        config.put("id.token.claim", "true");
        config.put("introspection.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("claim.name", "clientHost");
        config.put("jsonType.label", "String");
        mapper.setConfig(config);

        client.addProtocolMapper(mapper);
    }

    private void addClientIdMapper(ClientModel client) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName("Client ID");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usersessionmodel-note-mapper");

        Map<String, String> config = new HashMap<>();
        config.put("user.session.note", "client_id");
        config.put("id.token.claim", "true");
        config.put("introspection.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("claim.name", "client_id");
        config.put("jsonType.label", "String");
        mapper.setConfig(config);

        client.addProtocolMapper(mapper);
    }

    private void addClientScopes(RealmModel realm, ClientModel client) {
        // Add default client scopes
        String[] defaultScopes = {"web-origins", "acr", "vusmartmaps", "profile", "roles", "basic", "email"};
        for (String scopeName : defaultScopes) {
            ClientScopeModel scope = KeycloakModelUtils.getClientScopeByName(realm, scopeName);
            if (scope != null) {
                client.addClientScope(scope, true);
            } else {
                LOG.warnf("Default client scope '%s' not found in realm '%s'", scopeName, realm.getName());
            }
        }

        // Add optional client scopes
        String[] optionalScopes = {"address", "phone", "offline_access", "microprofile-jwt"};
        for (String scopeName : optionalScopes) {
            ClientScopeModel scope = KeycloakModelUtils.getClientScopeByName(realm, scopeName);
            if (scope != null) {
                client.addClientScope(scope, false);
            } else {
                LOG.warnf("Optional client scope '%s' not found in realm '%s'", scopeName, realm.getName());
            }
        }
    }

    private void addClientRoles(ClientModel client) {
        // Add uma_protection role
        RoleModel umaRole = client.getRole("uma_protection");
        if (umaRole == null) {
            umaRole = client.addRole("uma_protection");
            umaRole.setDescription("UMA Protection role for omniagent-client");
            LOG.infof("Added 'uma_protection' role to client '%s'", client.getClientId());
        } else {
            LOG.infof("Role 'uma_protection' already exists for client '%s'", client.getClientId());
        }
    }

    private void enableAuthorizationServices(KeycloakSession session, ClientModel client) {
        try {
            // Set authorization services attribute - this is the simplest approach
            client.setAttribute("authorizationServicesEnabled", "true");
            LOG.infof("Set authorization services attribute for client '%s'", client.getClientId());
        } catch (Exception e) {
            LOG.warnf(e, "Failed to set authorization services attribute for client '%s'. Client will work without authorization services.", client.getClientId());
        }
    }

    private void addServiceAccountUser(KeycloakSession session, RealmModel realm) {
        String serviceAccountUsername = "service-account-omniagent-client";
        String clientId = "omniagent-client";

        try {
            ClientModel omniagentClientModel = realm.getClientByClientId(clientId);

            if (omniagentClientModel == null) {
                LOG.errorf("Cannot create service account: Client '%s' not found in realm '%s'", clientId, realm.getName());
                return;
            }

            UserModel serviceAccount = session.users().getUserByUsername(realm, serviceAccountUsername);

            if (serviceAccount != null) {
                LOG.infof("Service account user '%s' already exists in realm '%s'. Skipping.",
                        serviceAccountUsername, realm.getName());

                if (!omniagentClientModel.getId().equals(serviceAccount.getServiceAccountClientLink())) {
                    LOG.infof("Updating service_account_client_link to correct UUID for '%s'", serviceAccountUsername);
                    serviceAccount.setServiceAccountClientLink(omniagentClientModel.getId());
                }
                return;
            }

            LOG.infof("Adding service account user '%s' to realm '%s'", serviceAccountUsername, realm.getName());
            serviceAccount = session.users().addUser(realm, serviceAccountUsername);

            serviceAccount.setEnabled(true);
            serviceAccount.setEmailVerified(false);
            serviceAccount.setServiceAccountClientLink(omniagentClientModel.getId());
            serviceAccount.setCreatedTimestamp(System.currentTimeMillis());

            // Add realm roles
            RoleModel defaultRole = realm.getRole("default-roles-vunet");
            if (defaultRole != null) {
                serviceAccount.grantRole(defaultRole);
                LOG.infof("Granted realm role 'default-roles-vunet' to service account '%s'", serviceAccountUsername);
            } else {
                LOG.warnf("Default realm role 'default-roles-vunet' not found in realm '%s'", realm.getName());
            }

            // Add client role
            ClientModel omniagentClient = realm.getClientByClientId("omniagent-client");
            if (omniagentClient != null) {
                RoleModel umaRole = omniagentClient.getRole("uma_protection");
                if (umaRole != null) {
                    serviceAccount.grantRole(umaRole);
                    LOG.infof("Granted client role 'uma_protection' to service account '%s'", serviceAccountUsername);
                } else {
                    LOG.warnf("Client role 'uma_protection' not found for client 'omniagent-client'");
                }
            } else {
                LOG.warnf("Client 'omniagent-client' not found when trying to grant roles to service account");
            }

            LOG.infof("Successfully added service account user '%s' to realm '%s'",
                    serviceAccountUsername, realm.getName());
        } catch (Exception e) {
            LOG.errorf(e, "Failed to add service account user '%s' in realm '%s'",
                    serviceAccountUsername, realm.getName());
            throw e; // Re-throw to be caught by parent try-catch
        }
    }
}
