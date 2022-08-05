package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.sql.Date;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();
    }

    private SignedJWT buildAndSignJWT(JWTClaimsSet claimsSet)
        throws JOSEException
    {
        return null;
    }

    private void verifyJWT(SignedJWT jwt)
        throws JOSEException, BadJOSEException
    {

    }

    public String buildAccessToken(User user) throws JOSEException {
        // Create the expiration time based on value that will be obtained from the application.yml file.
        Instant expireTime = Instant.now().plus(jwtManager.getAccessTokenExpire());

        // Create JWTClaimSet.
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .expirationTime(Date.from(expireTime))
                .claim(JWTManager.CLAIM_ID, user.getId())
                .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                .issueTime(Date.from(Instant.now()))
                .build();

        // Create JWSHeader.
        JWSHeader header = new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                .keyID(jwtManager.getEcKey().getKeyID())
                .type(JWTManager.JWS_TYPE)
                .build();

        // Create a serialized SignedJWT.
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());
        return signedJWT.serialize();
    }

    public void verifyAccessToken(String jws)
    {
        try {
            // Parse the string back into a SignedJWT.
            SignedJWT signedJWT = SignedJWT.parse(jws);

            // Verify that the token is valid and has been issued. Errors can be thrown here.
            signedJWT.verify(jwtManager.getVerifier());

            // Check that the claims are consistent with what we expect. Errors can be thrown here.
            jwtManager.getJwtProcessor().process(signedJWT, null);

            // Logic to check expiration time.
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            System.out.println(jwtClaimsSet.getExpirationTime());

            Instant current = Instant.now();
            if (current.isAfter(jwtClaimsSet.getExpirationTime().toInstant())){
                throw new ResultError(IDMResults.ACCESS_TOKEN_IS_EXPIRED);
            }
        }
        catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
            throw new ResultError(IDMResults.ACCESS_TOKEN_IS_INVALID);
        }
    }

    public RefreshToken buildRefreshToken(User user)
    {
        // Create expiration time and max lifetime to be stored into the refresh token.
        Instant expireTime = Instant.now().plus(jwtManager.getAccessTokenExpire());
        Instant maxLife = Instant.now().plus(jwtManager.getMaxRefreshTokenLifeTime());

        // Create Refresh Token:
        return new RefreshToken()
                .setToken(UUID.randomUUID().toString())
                .setTokenStatus(TokenStatus.ACTIVE)
                .setExpireTime(expireTime)
                .setMaxLifeTime(maxLife);
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        return Instant.now().isAfter(refreshToken.getExpireTime());
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {

    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
