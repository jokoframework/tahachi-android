package io.github.jokoframework.tahachi.repository;

import io.github.jokoframework.tahachi.dto.JokoBaseResponse;
import io.github.jokoframework.tahachi.dto.LoginResponse;
import io.github.jokoframework.tahachi.dto.request.JokoLoginRequest;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Header;
import retrofit2.http.POST;

import static io.github.jokoframework.tahachi.util.TahachiConstants.HEADER_AUTH;

public interface JokoBackendService {

    @GET("/api/secure/lock-desktop")
    Call<JokoBaseResponse> lockDesktop(@Header(HEADER_AUTH) String token);

    @GET("/api/secure/unlock-desktop")
    Call<JokoBaseResponse> unlockDesktop(@Header(HEADER_AUTH) String token);

    @POST("/api/login")
    Call<LoginResponse> login(@Body JokoLoginRequest loginRequest);

    @POST("/api/token/user-access")
    Call<LoginResponse> userAccess(@Header(HEADER_AUTH) String refreshToken);
}
