var logger = org.jboss.logging.Logger.getLogger("vunet.policy.evaluate-privileges");
var Collectors = java.util.stream.Collectors;
var HashMap = java.util.HashMap;
var HashSet = java.util.HashSet;

// Implicit privilege mappings: granting privilege -> array of privileges it grants
var implicitPrivilegeMappings = {
  'alerts:read': ['dataModel:read', 'definitions:read', 'preferences:read'],
  "apiKey:read": ["users:read", "serviceAccount:read"],
  "apiKey:write": ["users:read", "users:write", "users:manageBulkObjects", "serviceAccount:read", "serviceAccount:write"],
  'alerts:write': ['dataModel:read', 'definitions:read', 'preferences:read'],
  'dashboards:admin': ['dashboards:write', 'dataModel:read', 'insights:read', 'utm:read', 'dataSource:manage'],
  'dashboards:write': ['dataModel:read', 'insights:read', 'utm:read'],
  'dataExtraction:read': ['dataModel:read'],
  'dataExtraction:write': ['dataModel:read'],
  "dataModel:manageDataStore": ["dataModel:write", "dataModel:read", "preferences:read"],
  "dataModel:write": ["dataModel:read", "preferences:read"],
  "dataModel:read": ["preferences:read"],
  'dataSource:manage': ['dashboards:admin', 'dataModel:read', 'insights:read', 'utm:read'],
  'events:read': ['preferences:read'],
  'events:write': ['preferences:read', 'users:read'],
  'insights:modifySystemResources': ['insights:read', 'insights:write'],
  'insights:read': ['dataModel:read'],
  'insights:write': ['dataModel:read'],
  'mobileDashboards:read': ['dataModel:read', 'insights:read'],
  'mobileDashboards:write': ['dataModel:read', 'insights:read'],
  'reports:read': ['dataModel:read', 'definitions:read', 'preferences:read'],
  'reports:write': ['dataModel:read', 'definitions:read', 'preferences:read'],
  'resources:manage': ['alerts:read', 'dataModel:read', 'insights:read', 'utm:read'],
  "serviceAccount:read": ["users:read"],
  "serviceAccount:write": ["users:read","users:write","users:manageBulkObjects"],
  'utm:read': ['dataModel:read'],
  'utm:write': ['dataModel:read'],
  'vumodule:modifySources': ['alerts:read', 'definitions:read', 'vumodule:read', 'dataModel:read'],
  'vumodule:read': ['definitions:read'],
  'vumodule:write': ['alerts:read', 'dataModel:read', 'definitions:read', 'vumodule:modify_sources']
};

// Convert to Java HashMap for better performance
var implicitPrivilegeMap = new HashMap();
for (var grantingPrivilege in implicitPrivilegeMappings) {
  var grantedPrivileges = new HashSet();
  for (var i = 0; i < implicitPrivilegeMappings[grantingPrivilege].length; i++) {
    grantedPrivileges.add(implicitPrivilegeMappings[grantingPrivilege][i]);
  }
  implicitPrivilegeMap.put(grantingPrivilege, grantedPrivileges);
}

var URN_PREFIX = 'vrn:vusmartmaps:resources:';

function toUrn(rs) {
  return URN_PREFIX + rs;
}

function fromUrn(urn) {
  if (urn.startsWith(URN_PREFIX)) {
    return urn.substring(URN_PREFIX.length);
  }
  return urn; // return as-is if not a URN
}
// Get explicit privileges from user groups
function _getExplicitPrivileges(user) {
  return user.getGroupsStream()
    .flatMap(function (group) {
      return group.getAttributeStream("privilege");
    })
    .collect(Collectors.toSet());
}

// Mirrors _getExplicitPrivileges(user), but the source of groups is a
// Service Account's `group_ids` claim (resolved against the realm) instead
// of a real user's group memberships.
function _getExplicitPrivilegesFromGroupIds(groupIds, realm) {
  var explicitPrivileges = new HashSet();

  for (var i = 0; i < groupIds.length; i++) {
    var groupId = groupIds[i];
    var group = realm.getGroupById(groupId);

    if (group === null || group === undefined) {
      logger.warnv("group_ids claim referenced unknown/unresolvable group id `{0}` (skipping)", groupId);
      continue;
    }

    var groupPrivileges = group.getAttributeStream("privilege").collect(Collectors.toSet());
    explicitPrivileges.addAll(groupPrivileges);
  }

  return explicitPrivileges;
}

// Extend explicit privileges with implicit privileges
function _extendExplicitPrivileges(explicitPrivileges) {
  var extendedPrivileges = new HashSet(explicitPrivileges);
  var iterator = explicitPrivileges.iterator();

  while (iterator.hasNext()) {
    var privilegeUrn = iterator.next();
    var privilege = fromUrn(privilegeUrn); // Strip URN prefix for lookup
    var splitPrivilege = privilege.split(':');
    var resource = splitPrivilege[0];
    var scope = splitPrivilege[1];

    // automatically assign read scope if write scope is present
    if (scope === "write") {
      extendedPrivileges.add(toUrn(resource + ":read"));
    }

    // Check if this privilege grants any other privileges
    var grantedPrivileges = implicitPrivilegeMap.get(privilege);
    if (grantedPrivileges !== null) {
      var grantedIterator = grantedPrivileges.iterator();
      while (grantedIterator.hasNext()) {
        var grantedPrivilege = grantedIterator.next();
        extendedPrivileges.add(toUrn(grantedPrivilege)); // Add URN prefix back
      }
    }
  }

  return extendedPrivileges;
}

function getUserPrivileges(user) {
  var explicitPrivileges = _getExplicitPrivileges(user)
  var extendedPrivileges = _extendExplicitPrivileges(explicitPrivileges);
  var printablePrivileges = extendedPrivileges.stream().map(fromUrn).collect(Collectors.joining(", "));

  logger.debugv("User {0} has privileges: {1}", user.getUsername(), printablePrivileges);
  return extendedPrivileges;
}

// Mirrors getUserPrivileges(user) for the group_ids-based Service Account flow.
function getPrivilegesForGroupIds(groupIds, realm) {
  var explicitPrivileges = _getExplicitPrivilegesFromGroupIds(groupIds, realm);
  var extendedPrivileges = _extendExplicitPrivileges(explicitPrivileges);
  var printablePrivileges = extendedPrivileges.stream().map(fromUrn).collect(Collectors.joining(", "));

  logger.debugv("group_ids [{0}] resolve to privileges: {1}", groupIds.join(", "), printablePrivileges);
  return extendedPrivileges;
}

function _evaluateForAdmin(identity) {
  if (identity.hasRealmRole('admin')) {
    logger.info("Granting all permissions to admin");
    return true;
  } else {
    logger.debugv("User {0} is not an admin, proceeding with privilege evaluation for normal user", identity.getId());
    return false;
  }
}

function _evaluateForUser(user, userId, privilege) {
  if (user === null || user === undefined) {
    logger.warnv("No user found for identity id: {0}", userId);
    return false;
  } else {
    var privileges = getUserPrivileges(user);
    var result = privileges.contains(privilege);
    var resultString = result ? "granted" : "denied";
    logger.infov("checking is user `{0}` has privilege `{1}`: {2}", user.getUsername(), fromUrn(privilege), resultString);

    return result;
  }
}

// Evaluates a privilege against a Service Account's group_ids claim instead
// of a real user's group memberships. Only ever invoked when the request
// carries `group_ids` AND was authenticated as the trusted `vusmartmaps`
// client -- see the guard at the bottom of this script.
function _evaluateForGroupIds(groupIds, realm, privilege) {
  var privileges = getPrivilegesForGroupIds(groupIds, realm);
  var result = privileges.contains(privilege);
  var resultString = result ? "granted" : "denied";
  logger.infov("checking if group_ids [{0}] has privilege `{1}`: {2}", groupIds.join(", "), fromUrn(privilege), resultString);

  return result;
}

function evaluate(identity, user, privilege) {
  if (_evaluateForAdmin(identity)) {
    $evaluation.grant();
  } else if (_evaluateForUser(user, identity.getId(), privilege)) {
    $evaluation.grant();
  } else {
    $evaluation.denyIfNoEffect();
  }
}

// Reads the `group_ids` claim (from claim_token, folded into context
// attributes by DefaultEvaluationContext). Returns:
//   - null       => claim not present at all
//   - [] or [..] => claim present (possibly empty) -- caller must treat
//                   presence as "engage the group_ids branch"
function _extractGroupIds(contextAttributes) {
  var entry = contextAttributes.getValue('group_ids');

  if (entry === null || entry === undefined) {
    return null;
  }

  var groupIds = [];
  for (var i = 0; i < entry.size(); i++) {
    groupIds.push(entry.asString(i));
  }
  return groupIds;
}

// True only when the request was authenticated (client-credentials, via
// client secret) as the trusted `vusmartmaps` client -- Keycloak itself
// guarantees a caller cannot spoof another client's kc.client.id/azp.
function _isTrustedServiceClient(contextAttributes) {
  var entry = contextAttributes.getValue('kc.client.id');
  return entry !== null && entry !== undefined && entry.size() > 0 && entry.asString(0) === 'vusmartmaps';
}

// Authorization evaluation logic
var _context = $evaluation.getContext();
var _contextAttributes = _context.getAttributes();

// Resource and scope information
var _permission = $evaluation.getPermission();
var _resource = _permission.getResource().getName();
var _scope = _permission.getScopes().toArray()[0].getName(); // cairo APIs request only one scope at max for any API endpoint
var privilege = _resource + ':' + _scope;

// Realm and Identity information
var _authProvider = $evaluation.getAuthorizationProvider();
var _realm = _authProvider.getRealm();
var identity = _context.getIdentity();

logger.debug("---Starting evaluation---")
logger.debugv("Evaluating privilege: {0}", fromUrn(privilege));

var _groupIds = _extractGroupIds(_contextAttributes);
var _trustedServiceClient = _isTrustedServiceClient(_contextAttributes);

if (_groupIds !== null && _trustedServiceClient) {
  // Service Account flow: caller is the trusted `vusmartmaps` client
  // presenting group_ids on behalf of a Traefik/Auth-Service-issued
  // internal token. Bypasses the admin short-circuit and user lookup
  // entirely -- this is not a real Keycloak user.
  logger.debugv("Evaluating privilege {0} via group_ids claim ({1} group id(s)) for trusted client `vusmartmaps`",
    fromUrn(privilege), _groupIds.length);

  if (_evaluateForGroupIds(_groupIds, _realm, privilege)) {
    $evaluation.grant();
  } else {
    $evaluation.denyIfNoEffect();
  }
} else {
  if (_groupIds !== null && !_trustedServiceClient) {
    logger.warnv("group_ids claim present but caller is not authenticated as trusted client `vusmartmaps`; ignoring claim and falling back to standard user-based evaluation");
  }

  // Realm, Identity, and User information
  var user = _authProvider.getKeycloakSession().users().getUserById(
    _realm,
    identity.getId()
  );

  evaluate(identity, user, privilege);
}

logger.debug("---Ending evaluation---");