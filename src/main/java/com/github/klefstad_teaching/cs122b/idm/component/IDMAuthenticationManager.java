package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;

    @Autowired
    public IDMAuthenticationManager(IDMRepo repo)
    {
        this.repo = repo;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public User selectAndAuthenticateUser(String email, char[] password)
    {
        return repo.existUser(email);
    }

    public void createAndInsertUser(String email, char[] password)
    {
        // Register a user, if the email exist within the database, throw
        // user already exist error.
        try{
            byte[] salt = genSalt();
            byte[] encodedPassword = hashPassword(password, salt);
            String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);
            String base64EncodedHashedSalt = Base64.getEncoder().encodeToString(salt);
            repo.insertUser(email, base64EncodedHashedSalt, base64EncodedHashedPassword);
        }
        catch (org.springframework.dao.DuplicateKeyException e){
            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);
        }
    }

    public void matchExistingUser(String email, char[] password){
        // Take the login information and check whether the user exist,
        // if so salt and hash its password and begin comparisons.
        User users = repo.existUser(email);
        String salt = users.getSalt();
        byte[] decodedPassword = hashPassword(password, salt);
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(decodedPassword);

        // If the entered password does not match the salt and hashed one stored in database
        // throw invalid credentials.
        if (!base64EncodedHashedPassword.equals(users.getHashedPassword())){
            throw new ResultError((IDMResults.INVALID_CREDENTIALS));
        }

        // If the user is banned from the site.
        if (users.getUserStatus() == UserStatus.BANNED){
            throw new ResultError(IDMResults.USER_IS_BANNED);
        }

        // If the user is locked from the site.
        if (users.getUserStatus() == UserStatus.LOCKED){
            throw new ResultError(IDMResults.USER_IS_LOCKED);
        }
    }

    public void insertRefreshToken(RefreshToken refreshToken, String email)
    {
        // Call function to insert the refresh token into the database.
        repo.insertRefreshToken(refreshToken, email);
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        return repo.existRefreshToken(token);
    }

    public void updateRefreshTokenStatus(RefreshToken refreshToken){
        repo.updateRefreshToken(refreshToken.getToken());
    }

    public User returnUserFromRefreshToken(String token){
        RefreshToken refreshToken = repo.existRefreshToken(token);
        if (refreshToken == null){
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);
        }
        return repo.getUserFromRefreshToken(token, refreshToken.getId());
    }

    public void updateRefreshTokenExpireTime(RefreshToken token)
    {
        repo.updateRefreshTokenExpiretime(token.getToken());
    }

    public void expireRefreshToken(RefreshToken token)
    {
    }

    public void revokeRefreshToken(RefreshToken token)
    {
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        return null;
    }
}
