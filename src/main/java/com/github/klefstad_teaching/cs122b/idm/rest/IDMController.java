package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.AuthenticateRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.request.RefreshRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.request.RegisterRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.AuthenticateResponseModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.LoginResponseModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.RefreshResponseModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponseModel;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.transform.Result;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@RestController
public class IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;

    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponseModel> registerUser(@RequestBody RegisterRequestModel request)
    {
        String email = request.getEmail();
        char[] password = request.getPassword();

        // This will throw any errors based on the input information.
        Validate valid = new Validate();
        valid.validEmailorPassword(email, password, authManager);

        // If we run into no errors when registering a user, we will add them to the database
        // and respond to the request with success.
        authManager.createAndInsertUser(email, password);

        // Create our response:
        RegisterResponseModel body = new RegisterResponseModel()
                .setResult(IDMResults.USER_REGISTERED_SUCCESSFULLY);

        return ResponseEntity
                .status(body.getResult().status())
                .body(body);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseModel> loginUser(@RequestBody LoginRequestModel request) throws JOSEException {
        // Create Access Token:
        String email = request.getEmail();
        char[] password = request.getPassword();

        // This will throw any errors based on the input information.
        Validate valid = new Validate();
        valid.validEmailorPasswordLogin(email, password, authManager);

        // If we run into no errors, salt and hash the password to check if it matches
        // hashed password in the database. Throw error if not the same.
        User users = authManager.selectAndAuthenticateUser(email, password);
        if (users == null){
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }
        String accessToken = jwtManager.buildAccessToken(users);

        // Check if passwords match.
        authManager.matchExistingUser(email, password);

        // Create Refresh Token:
        RefreshToken refreshToken = jwtManager.buildRefreshToken(users);

        // Insert our refresh token into our database:
        authManager.insertRefreshToken(refreshToken, email);

        // Create our response:
        LoginResponseModel body = new LoginResponseModel()
                .setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY)
                .setAccessToken(accessToken)
                .setRefreshToken(refreshToken.getToken());

        return ResponseEntity
                .status(body.getResult().status())
                .body(body);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponseModel> refresh(@RequestBody RefreshRequestModel request) throws JOSEException {

        // Check if valid length of refresh token:
        if (request.getRefreshToken().length() < 36 | request.getRefreshToken().length() > 36){
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH);
        }

        // Check if valid form of refresh token:
        try{
            UUID uuid = UUID.fromString(request.getRefreshToken());
        }
        catch (IllegalArgumentException e){
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT);
        }

        // Check if the refresh token exist:
        RefreshToken refreshToken = authManager.verifyRefreshToken(request.getRefreshToken());
        if (refreshToken == null){
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);
        }

        // Check if the refresh token has already expired:
        if (refreshToken.getTokenStatus() == TokenStatus.EXPIRED){
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        }

        // Check if the refresh token is revoked:
        if (refreshToken.getTokenStatus() == TokenStatus.REVOKED){
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_REVOKED);
        }

        // Check if current time is after expire time or max lifetime:
        if (Instant.now().isAfter(refreshToken.getExpireTime()) | Instant.now().isAfter(refreshToken.getMaxLifeTime())){
            // Update the refresh token status to expired:
            authManager.updateRefreshTokenStatus(refreshToken);

            // Once token status is updated, we need to construct the response with a new access
            // token pertaining to the user who was given this refresh token.
            User users = authManager.returnUserFromRefreshToken(request.getRefreshToken());
            if (users == null){
                throw new ResultError(IDMResults.USER_NOT_FOUND);
            }
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        }

        // Update refresh token expire time:
        authManager.updateRefreshTokenExpireTime(refreshToken);

        // Grab the new refreshed token:
        RefreshToken refreshedToken = authManager.verifyRefreshToken(refreshToken.getToken());

        // Create our response:
        RefreshResponseModel body = new RefreshResponseModel()
                .setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN)
                .setRefreshToken(request.getRefreshToken());

        return ResponseEntity
                .status(body.getResult().status())
                .body(body);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateResponseModel> authenticate(@RequestBody AuthenticateRequestModel request){

        // Check if the access token given in the request body is valid, if invalid
        // this function call will catch the exception and throw either
        // access token is invalid or expired.
        jwtManager.verifyAccessToken(request.getAccessToken());

        // Create our response.
        AuthenticateResponseModel body = new AuthenticateResponseModel()
                .setResult(IDMResults.ACCESS_TOKEN_IS_VALID);

        return ResponseEntity
                .status(body.getResult().status())
                .body(body);
    }
}
