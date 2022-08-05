package com.github.klefstad_teaching.cs122b.idm.model.request;

public class AuthenticateRequestModel {

    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public AuthenticateRequestModel setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }
}
