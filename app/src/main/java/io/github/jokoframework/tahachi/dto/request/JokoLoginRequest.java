package io.github.jokoframework.tahachi.dto.request;

public class JokoLoginRequest {
    private String username;
    private String password;

    public JokoLoginRequest(String username, String password) {
        setPassword(password);
        setUsername(username);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
