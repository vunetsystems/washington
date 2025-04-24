package org.keycloak.migration.migrators;

import org.keycloak.migration.MigrationProvider;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.List;

public class MigrateTo25_0_13 implements Migration{
    public static final ModelVersion VERSION = new ModelVersion("999.0.0-SNAPSHOT");

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
        MigrationProvider migrationProvider = session.getProvider(MigrationProvider.class);

        ClientScopeModel basicScope = KeycloakModelUtils.getClientScopeByName(realm, "basic");
        if (basicScope == null) {
            basicScope = migrationProvider.addOIDCBasicClientScope(realm);
            session.clients().addClientScopeToAllClients(realm, basicScope, true);
        } else {
            System.out.println("Client scope '%s' already exists in the realm. Please migrate this realm manually if you need basic claims in your tokens.");
        }

        // 🔁 Update 'forms' flow
        AuthenticationFlowModel formsFlow = realm.getFlowByAlias("forms");
        if (formsFlow != null) {
            List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutionsStream(formsFlow.getId()).toList();

            for (AuthenticationExecutionModel execution : executions) {
                if ("auth-username-password-form".equals(execution.getAuthenticator())) {
                    execution.setAuthenticator("custom-username-password-form");
                    realm.updateAuthenticatorExecution(execution);
                }
            }
        } else {
            System.out.println("Flow 'forms' not found in realm '%s'. Skipping authenticator update.");
        }
    }
}
