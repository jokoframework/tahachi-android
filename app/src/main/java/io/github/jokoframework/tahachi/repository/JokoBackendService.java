package io.github.jokoframework.tahachi.repository;

import io.github.jokoframework.tahachi.dto.JokoBaseResponse;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Header;

import static io.github.jokoframework.tahachi.util.TahachiConstants.HEADER_AUTH;

public interface JokoBackendService {

    @GET("/api/secure/lock-desktop")
    Call<JokoBaseResponse> lockDesktop(@Header(HEADER_AUTH) String token);

    @GET("/api/secure/unlock-desktop")
    Call<JokoBaseResponse> unlockDesktop(@Header(HEADER_AUTH) String token);
}
