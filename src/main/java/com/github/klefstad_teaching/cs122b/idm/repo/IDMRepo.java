package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.RegisterRequestModel;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponseModel;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
//import com.sun.org.apache.xalan.internal.xsltc.compiler.util.Type;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.sql.Date;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Component
public class IDMRepo
{

    private final NamedParameterJdbcTemplate template;

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }

    public User existUser(String email){
        // Query for a user by checking the database if the email exist, if not return null.
        try {
            List<User> users = this.template.query("SELECT id, email, user_status_id, salt, hashed_password FROM idm.user WHERE email=:email;", new MapSqlParameterSource()
                    .addValue("email", email, Types.VARCHAR), (rs, rowNum) ->
                    new User()
                            .setId(rs.getInt("id"))
                            .setEmail(rs.getString("email"))
                            .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                            .setSalt(rs.getString("salt"))
                            .setHashedPassword(rs.getString("hashed_password")));
            return users.get(0);
        }
        catch (Exception e){
            return null;
        }
    }

    public void insertUser(String email, String salt, String hashed_password){
        // Insert into the idm.user table the users values/contents.
        int rowsupdated = this.template.update("INSERT INTO idm.user (email, user_status_id, salt, hashed_password)" +
                "VALUES (:email, :user_status_id, :salt, :hashed_password)",
                new MapSqlParameterSource()
                        .addValue("email", email, Types.VARCHAR)
                        .addValue("user_status_id", 1, Types.INTEGER)
                        .addValue("salt", salt, Types.CHAR)
                        .addValue("hashed_password", hashed_password, Types.CHAR));
    }

    public void insertRefreshToken(RefreshToken refreshToken, String email){
        // Check if user exist else throw that the user is not found.
        User users = existUser(email);
        if (users == null){
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }

        // Begin to insert into the idm.refresh_token table by inserting into its by taking values
        // from refreshToken and the user.
        int rowsupdated = this.template.update("INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time)" +
                "VALUES(:token, :user_id, :token_status_id, :expire_time, :max_life_time)",
                new MapSqlParameterSource()
                .addValue("token", refreshToken.getToken(), Types.CHAR)
                        .addValue("user_id", users.getId(), Types.INTEGER)
                .addValue("token_status_id", refreshToken.getTokenStatus().id(), Types.INTEGER)
                .addValue("expire_time", Timestamp.from(refreshToken.getExpireTime()), Types.TIMESTAMP)
                .addValue("max_life_time", Timestamp.from(refreshToken.getMaxLifeTime()),Types.TIMESTAMP));
    }

    public RefreshToken existRefreshToken(String token){
        try{
            List<RefreshToken> refreshToken = this.template.query("SELECT id, token, user_id, token_status_id, expire_time, max_life_time FROM idm.refresh_token WHERE token=:token;",
                    new MapSqlParameterSource()
                            .addValue("token", token, Types.CHAR), (rs, rowNum) ->
                            new RefreshToken()
                                    .setId(rs.getInt("id"))
                                    .setToken(rs.getString("token"))
                                    .setUserId(rs.getInt("user_id"))
                                    .setTokenStatus(TokenStatus.fromId(rs.getInt("token_status_id")))
                                    .setExpireTime(rs.getTimestamp("expire_time").toInstant())
                                    .setMaxLifeTime(rs.getTimestamp("max_life_time").toInstant()));
            return refreshToken.get(0);
        }
        catch (Exception e){
            return null;
        }
    }

    public void updateRefreshToken(String token){
        int rowsupdated = this.template.update("UPDATE idm.refresh_token rt SET rt.token_status_id = 2 WHERE rt.token LIKE :token",
                new MapSqlParameterSource()
                        .addValue("token", token, Types.CHAR));
    }

    public void updateRefreshTokenExpiretime(String token){
        RefreshToken refreshToken = existRefreshToken(token);
        if (refreshToken == null){
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);
        }
        Instant expire_time = refreshToken.getExpireTime().plus(Duration.ofHours(2));
        int rowsupdated = this.template.update("UPDATE idm.refresh_token SET expire_time = :expire_time  WHERE token = :token",
                new MapSqlParameterSource()
                        .addValue("expire_time", Timestamp.from(expire_time) ,Types.TIMESTAMP)
                        .addValue("token", token, Types.CHAR));
    }

    public User getUserFromRefreshToken(String token, int id){
        try{
            List<User> users = this.template.query("SELECT * FROM idm.user WHERE id=:id;",
                    new MapSqlParameterSource().addValue("id", id, Types.INTEGER), (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password")));
            return users.get(0);
        }
        catch (Exception e){
            return null;
        }

    }
}
