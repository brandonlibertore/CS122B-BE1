package com.github.klefstad_teaching.cs122b.idm.model.response;
import com.github.klefstad_teaching.cs122b.core.result.Result;

public class RegisterResponseModel {

    private Result result;

    public Result getResult() {
        return this.result;
    }

    public RegisterResponseModel setResult(Result result) {
        this.result = result;
        return this;
    }
}
