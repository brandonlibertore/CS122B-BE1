package com.github.klefstad_teaching.cs122b.idm.model.request;

public class RegisterRequestModel {

    private String email;
    private char[] password;

    public String getEmail() {
        return email;
    }

    public RegisterRequestModel setEmail(String email) {
        this.email = email;
        return this;
    }

    public char[] getPassword() {
        return password;
    }

    public RegisterRequestModel setPassword(char[] password) {
        this.password = password;
        return this;
    }
}
