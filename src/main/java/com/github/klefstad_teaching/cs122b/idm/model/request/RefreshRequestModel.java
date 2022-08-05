package com.github.klefstad_teaching.cs122b.idm.model.request;

public class RefreshRequestModel {

    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }

    public RefreshRequestModel setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }
}
