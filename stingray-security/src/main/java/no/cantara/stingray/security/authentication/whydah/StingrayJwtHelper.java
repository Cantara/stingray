package no.cantara.stingray.security.authentication.whydah;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

/**
 * Location for JWT public key: https://whydahdev.cantara.no/oauth2/.well-known/jwks.json
 **/
public class StingrayJwtHelper {
    private static final Logger log = LoggerFactory.getLogger(StingrayJwtHelper.class);

    final String oauth2Uri;
    final String token;
    final DecodedJWT jwt;

    public StingrayJwtHelper(String oauth2Uri, String token) {
        this(oauth2Uri, token, JWT.decode(token));
    }

    public StingrayJwtHelper(String oauth2Uri, String token, DecodedJWT jwt) {
        this.oauth2Uri = oauth2Uri;
        this.token = token;
        this.jwt = JWT.decode(token);
    }

    public boolean isExpiredOrInvalid(String token) {
        try {
            Long time = getClaimFromJwtToken("exp", Long.class);
            return time * 1000L <= System.currentTimeMillis();
        } catch (Exception ex) {
            return true;
        }
    }

    public String getAppTokenFromJwtToken() throws JwkException {
        return getClaimFromJwtToken("app_token", String.class);
    }

    public String getUserNameFromJwtToken() throws JwkException {
        return getClaimFromJwtToken("sub", String.class);
    }

    public String getUserTokenFromJwtToken() throws JwkException {
        return getClaimFromJwtToken("usertoken_id", String.class);
    }

    public String getCustomerRefFromJwtToken() throws JwkException {
        return getClaimFromJwtToken("customer_ref", String.class);
    }

    public <T> T getClaimFromJwtToken(String claimName, Class<T> requiredType) throws JwkException {
        String oauth2Issuer = oauth2Uri;
        JwkProvider provider = new JwkProviderBuilder(oauth2Issuer)
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES).build();
        Jwk jwk = provider.get(jwt.getKeyId());

        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(oauth2Issuer)
                .build();
        DecodedJWT djwt = verifier.verify(jwt);
        return djwt.getClaim(claimName).as(requiredType);
    }
}
