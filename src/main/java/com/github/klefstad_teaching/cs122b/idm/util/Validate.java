package com.github.klefstad_teaching.cs122b.idm.util;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.text.ParseException;

@Component
public final class Validate
{
    public void validEmailorPassword(String email, char[] password, IDMAuthenticationManager authManager){
        // If entered email string was left empty/null
        if (email == null){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        // If entered password char array was left empty/null
        if (password == null){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        // If entered email does not have the proper length of 6-32 (inclusive)
        if (email.length() < 6 || email.length() > 32){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
        }

        // If entered email does not match the email format
        if (!email.matches("^[a-zA-z0-9]+[@][a-zA-z0-9]+[.][a-zA-z0-9]+$")){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        // If entered password does not have the propper length of 10-20 (inclusive)
        if (password.length < 10 || password.length > 20){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        // If enter password does not match the password format
        boolean upper = false;
        boolean lower = false;
        boolean number = false;
        for (char c : password) {
            if (Character.isUpperCase(c)){
                upper = true;
            }
            else if (Character.isLowerCase(c)){
                lower = true;
            }
            else{
                number = true;
            }
        }
        if (!upper || !lower || !number){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        }

        // Check if this email already exist in the database. This function returns a User object from
        // a list of User objects meaning that the entered email exist within our database.
        User users = authManager.selectAndAuthenticateUser(email, password);
        if (users != null){
            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);
        }
    }

    public void validEmailorPasswordLogin(String email, char[] password, IDMAuthenticationManager authManager){
        // If entered email string was left empty/null
        if (email == null){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        // If entered password char array was left empty/null
        if (password == null){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        // If entered email does not have the proper length of 6-32 (inclusive)
        if (email.length() < 6 || email.length() > 32){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
        }

        // If entered email does not match the email format
        if (!email.matches("^[a-zA-z0-9]+[@][a-zA-z0-9]+[.][a-zA-z0-9]+$")){
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        // If entered password does not have the propper length of 10-20 (inclusive)
        if (password.length < 10 || password.length > 20){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        // If enter password does not match the password format
        boolean upper = false;
        boolean lower = false;
        boolean number = false;
        for (char c : password) {
            if (Character.isUpperCase(c)){
                upper = true;
            }
            else if (Character.isLowerCase(c)){
                lower = true;
            }
            else{
                number = true;
            }
        }
        if (!upper || !lower || !number){
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        }
    }
}
