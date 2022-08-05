package com.github.klefstad_teaching.cs122b.idm.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.klefstad_teaching.cs122b.core.result.Result;

public class RefreshResponseModel {

    private Result result;
    private String accessToken;
    private String refreshToken;

    public Result getResult() {
        return result;
    }

    public RefreshResponseModel setResult(Result result) {
        this.result = result;
        return this;
    }

    @JsonProperty("accessToken")
    public String getAccessToken() {
        return accessToken;
    }

    public RefreshResponseModel setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    @JsonProperty("refreshToken")
    public String getRefreshToken() {
        return refreshToken;
    }

    public RefreshResponseModel setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }
}
