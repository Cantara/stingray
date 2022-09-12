package no.cantara.stingray.security.authentication.whydah;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import net.whydah.sso.user.mappers.UserTokenMapper;
import net.whydah.sso.user.types.UserApplicationRoleEntry;
import net.whydah.sso.user.types.UserToken;
import no.cantara.stingray.security.authentication.DefaultStingrayApplicationAuthentication;
import no.cantara.stingray.security.authentication.DefaultStingrayAuthenticationResult;
import no.cantara.stingray.security.authentication.StingrayApplicationAuthentication;
import no.cantara.stingray.security.authentication.StingrayApplicationTag;
import no.cantara.stingray.security.authentication.StingrayApplicationTokenSession;
import no.cantara.stingray.security.authentication.StingrayAuthenticationManager;
import no.cantara.stingray.security.authentication.StingrayAuthenticationResult;
import no.cantara.stingray.security.authentication.StingrayCantaraUserAuthentication;
import no.cantara.stingray.security.authentication.StingrayUserAuthentication;
import no.cantara.stingray.security.authentication.UnauthorizedStingrayException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class WhydahStingrayAuthenticationManager implements StingrayAuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(WhydahStingrayAuthenticationManager.class);
    private static final Pattern appTokenIdPattern = Pattern.compile("<applicationtokenID>([^<]*)</applicationtokenID>");

    private final String oauth2Uri;
    private final StingrayApplicationTokenSession applicationTokenSession;
    private final StingrayWhydahService whydahService;
    private final String whydahAuthGroupUserRoleNameFix;
    private final String whydahAuthGroupApplicationTagName;

    public WhydahStingrayAuthenticationManager(String oauth2Uri, StingrayApplicationTokenSession applicationTokenSession, StingrayWhydahService whydahService, String whydahAuthGroupUserRoleNameFix, String whydahAuthGroupApplicationTagName) {
        this.oauth2Uri = oauth2Uri;
        this.applicationTokenSession = applicationTokenSession;
        this.whydahService = whydahService;
        this.whydahAuthGroupUserRoleNameFix = whydahAuthGroupUserRoleNameFix;
        this.whydahAuthGroupApplicationTagName = whydahAuthGroupApplicationTagName;
    }

    public StingrayWhydahService getWhydahService() {
        return whydahService;
    }

    public String getWhydahAuthGroupUserRoleNameFix() {
        return whydahAuthGroupUserRoleNameFix;
    }

    public String getWhydahAuthGroupApplicationTagName() {
        return whydahAuthGroupApplicationTagName;
    }

    @Override
    public StingrayUserAuthentication authenticateAsUser(final String authorizationHeader) throws UnauthorizedStingrayException {
        String authorization = authorizationHeader;
        if (authorization == null || authorization.isEmpty()) {
            throw new UnauthorizedStingrayException();
        }
        String usertokenid;
        String token = authorization.substring("Bearer ".length());
        String ssoId;
        String username;
        String customerRef;
        Supplier<String> forwardingTokenGenerator = () -> token; // forwarding incoming token by default
        Supplier<Map<String, String>> rolesGenerator;
        Supplier<UserToken> userTokenSupplier;
        if (token.length() > 50) {
            log.trace("Suspected JWT-token is {}", token);
        } else {
            log.trace("Suspected whydah-userticket is {}", token);
        }
        DecodedJWT decodedJWT = null;
        try {
            decodedJWT = JWT.decode(token);
            log.trace("token is a JWT token: {}", token);
        } catch (JWTDecodeException e) {
            log.trace("token is not a JWT token: {}", token);
        }
        if (decodedJWT != null) {
            try {
                log.debug("Resolving JWT-token");
                StingrayJwtHelper jwtUtils = new StingrayJwtHelper(oauth2Uri, token);
                ssoId = null; // lazy loaded from user-token
                username = jwtUtils.getUserNameFromJwtToken();
                customerRef = jwtUtils.getCustomerRefFromJwtToken();
                usertokenid = jwtUtils.getUserTokenFromJwtToken();
                final String theUserTokenId = usertokenid;
                UserTokenCacheEntry userTokenCacheEntry = new UserTokenCacheEntry(theUserTokenId);
                userTokenSupplier = userTokenCacheEntry::getUserToken;
                rolesGenerator = () -> {
                    UserToken userToken = userTokenCacheEntry.getUserToken();
                    if (userToken == null) {
                        return Collections.emptyMap();
                    }
                    Map<String, String> roleValueByName = userToken.getRoleList()
                            .stream()
                            .collect(Collectors.toMap(UserApplicationRoleEntry::getRoleName, UserApplicationRoleEntry::getRoleValue));
                    return roleValueByName;
                };
                log.trace("Resolved JWT-token. Found customerRef {} and usertokenid {}", customerRef, usertokenid);
            } catch (JwkException e) {
                log.warn("Token {} throws JwkException during authentication {} ", token, e);
                throw new UnauthorizedStingrayException();
            }
        } else {
            try {
                log.debug("Resolving Whydah-userticket");
                String userticket = token;
                final String userTokenFromUserTokenId = whydahService.getUserTokenByUserTicket(userticket);
                if (userTokenFromUserTokenId != null && UserTokenMapper.validateUserTokenMD5Signature(userTokenFromUserTokenId)) {
                    final UserToken userToken = UserTokenMapper.fromUserTokenXml(userTokenFromUserTokenId);
                    userTokenSupplier = () -> userToken;
                    usertokenid = userToken.getUserTokenId();
                    ssoId = userToken.getUid();
                    if (ssoId == null || ssoId.isEmpty()) {
                        log.debug("Unsuccessful resolving of user-authentication, ssoId is null or empty. ssoid '{}'", ssoId);
                        throw new UnauthorizedStingrayException();
                    }
                    username = userToken.getUserName();
                    customerRef = userToken.getPersonRef();
                    final String theUserTokenId = usertokenid;
                    final String theSsoId = ssoId;
                    final String theCustomerRef = customerRef;
                    forwardingTokenGenerator = () -> {
                        String forwardingUserTicket = whydahService.createTicketForUserTokenID(theUserTokenId);
                        if (forwardingUserTicket == null) {
                            throw new RuntimeException(String.format("Unable to generate user-ticket for user. ssoId=%s, customerRef=%s", theSsoId, theCustomerRef));
                        }
                        return forwardingUserTicket;
                    };
                    rolesGenerator = () -> {
                        Map<String, String> roleValueByName = userToken.getRoleList()
                                .stream()
                                .collect(Collectors.toMap(UserApplicationRoleEntry::getRoleName, UserApplicationRoleEntry::getRoleValue));
                        return roleValueByName;
                    };
                    log.debug("Resolved Whydah-userticket. Found customerRef {} and usertokenid {}", customerRef, usertokenid);
                } else {
                    log.debug("Unresolved Whydah-userticket! Got usertoken {}", userTokenFromUserTokenId);
                    throw new UnauthorizedStingrayException();
                }
            } catch (Exception ex) {
                log.debug("Exception", ex);
                if (ex instanceof UnauthorizedStingrayException) {
                    throw ex;
                }
                log.info("Token {} throws Exception during whydah-authentication {} ", token, ex);
                throw new UnauthorizedStingrayException();
            }
        }

        if (usertokenid == null || usertokenid.isEmpty()) {
            log.debug("Usertoken is null or empty");
            throw new UnauthorizedStingrayException();
        }

        boolean okUserSession = whydahService.validateUserTokenId(usertokenid);

        if (customerRef == null || customerRef.isEmpty()) {
            log.debug("Unsuccessful resolving of user-authentication, customerRef is null or empty. customerRef {}", customerRef);
            throw new UnauthorizedStingrayException();
        }
        if (!okUserSession) {
            log.debug("Unsuccessful resolving of user-authentication, okUserSession false.");
            throw new UnauthorizedStingrayException();
        }
        log.debug("Successful user authentication");

        return new StingrayCantaraUserAuthentication(ssoId, username, usertokenid, customerRef, forwardingTokenGenerator, rolesGenerator, whydahAuthGroupUserRoleNameFix, userTokenSupplier);
    }

    private class UserTokenCacheEntry {
        private final static int MAX_LOAD_ATTEMPTS = 1;
        private final String userTokenId;
        private final AtomicInteger loadsAttempted = new AtomicInteger(0);
        private final AtomicReference<UserToken> userTokenRef = new AtomicReference<>();

        UserTokenCacheEntry(String userTokenId) {
            this.userTokenId = userTokenId;
        }

        UserToken getUserToken() {
            if (userTokenRef.get() == null && loadsAttempted.get() < MAX_LOAD_ATTEMPTS) {
                synchronized (userTokenRef) {
                    if (userTokenRef.get() == null) {
                        UserToken userToken = load();
                        if (userToken == null) {
                            throw new RuntimeException("Unable to load UserToken");
                        }
                        userTokenRef.set(userToken);
                    }
                }
            }
            UserToken userToken = userTokenRef.get();
            return userToken; // can be null if load failed
        }

        private UserToken load() {
            try {
                UserToken userToken = whydahService.findUserTokenFromUserTokenId(userTokenId);
                return userToken;
            } finally {
                loadsAttempted.incrementAndGet();
            }
        }
    }

    @Override
    public StingrayApplicationAuthentication authenticateAsApplication(final String authorizationHeader) throws
            UnauthorizedStingrayException {
        String authorization = authorizationHeader;
        if (authorization == null || authorization.isEmpty()) {
            return null;
        }
        try {
            String token = authorization.substring("Bearer ".length());

            if (token.contains("<applicationtoken>")) {
                // assume that bearer token is application-token xml, extract the application-token-id from it
                Matcher m = appTokenIdPattern.matcher(token);
                if (m.find()) {
                    // Use only the application-token-id from the xml, we cannot trust anything else unless it was signed
                    String applicationTokenId = m.group(1);
                    log.trace("Resolved applicationTokenId {} from token {}", applicationTokenId, token);
                    return authenticateAsApplicationForApplicationTokenId(applicationTokenId);
                } else {
                    log.warn("Invalid application-token XML sent as bearer token. This is not a supported authentication mechanism. Token: {}", token);
                }
            } else {
                if (token.length() > 50) {
                    log.trace("Suspected JWT-token is {}", token);
                } else {
                    log.trace("Suspected whydah-application-token-id is {}", token);
                }
                try {
                    StingrayJwtHelper jwtUtils = new StingrayJwtHelper(oauth2Uri, token);
                    String applicationTokenId = jwtUtils.getAppTokenFromJwtToken();
                    if (applicationTokenId != null && !applicationTokenId.isEmpty()) {
                        log.trace("Found application token id {} in jwt token", applicationTokenId);
                        return authenticateAsApplicationForApplicationTokenId(applicationTokenId);
                    }
                } catch (JWTDecodeException e) {
                    log.trace("Not a jwt token: {}", token);
                } catch (JwkException e) {
                    log.warn("Unable to retrieve app_token from jwt token: {}", token);
                    return null;
                }

                // assume that bearer token is application-token-id
                return authenticateAsApplicationForApplicationTokenId(token);
            }
        } catch (Exception e) {
            log.error("Exception in attempt to resolve authorization, bearerToken: " + authorizationHeader, e);
        }
        return null;
    }

    private DefaultStingrayApplicationAuthentication authenticateAsApplicationForApplicationTokenId(String applicationTokenId) {
        final String applicationId = whydahService.getApplicationIdFromApplicationTokenId(applicationTokenId);
        log.trace("Lookup application from applicationTokenId {}. Id found {}", applicationTokenId, applicationId);
        if (applicationId != null) {
            return new DefaultStingrayApplicationAuthentication(applicationId, applicationTokenId, () -> {
                List<StingrayApplicationTag> tags = whydahService.getApplicationTagsFromApplicationTokenId(applicationTokenId);
                return tags;
            }, whydahAuthGroupApplicationTagName);
        } else {
            return null;
        }
    }

    @Override
    public StingrayAuthenticationResult authenticate(String authorizationHeader) {
        String authorization = authorizationHeader;
        if (authorization == null || authorization.isEmpty() || authorization.length() < 39) {
            return new DefaultStingrayAuthenticationResult(null);
        }
        String token = authorization.substring("Bearer ".length());
        if (isApplicationToken(token)) {
            try {
                StingrayApplicationAuthentication applicationAuthentication = authenticateAsApplication(authorization);
                return new DefaultStingrayAuthenticationResult(applicationAuthentication);
            } catch (UnauthorizedStingrayException e) {
                return new DefaultStingrayAuthenticationResult(null);
            }
        }

        //Assume jwt or whydah user token
        try {
            StingrayUserAuthentication userAuthentication = authenticateAsUser(authorization);
            return new DefaultStingrayAuthenticationResult(userAuthentication);
        } catch (UnauthorizedStingrayException e) {
            return new DefaultStingrayAuthenticationResult(null);
        }
    }

    @Override
    public StingrayApplicationTokenSession getApplicationTokenSession() {
        return applicationTokenSession;
    }

    private boolean isApplicationToken(String token) {
        if (token.contains("<applicationtoken>") || token.length() < 33) {
            return true;
        }
        // Check whether it is a jwt token with app_token
        try {
            StingrayJwtHelper jwtUtils = new StingrayJwtHelper(oauth2Uri, token);
            String appToken = jwtUtils.getAppTokenFromJwtToken();
            if (appToken != null && !appToken.isEmpty()) {
                log.debug("Found app token in jwt token");
                return true;
            }
        } catch (JWTDecodeException e) {
            log.debug("Not a jwt token");
        } catch (JwkException e) {
            log.debug("Unable to retrieve app_token from jwt token");
        }
        return false;
    }
}

