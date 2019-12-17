package io.github.jokoframework.tahachi.dto;

public class LoginResponse extends JokoBaseResponse {
    private String secret;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
