package io.github.jokoframework.tahachi.exceptions;

public class TahachiException extends RuntimeException {
    public TahachiException() {
    }

    public TahachiException(String message) {
        super(message);
    }

    public TahachiException(String message, Throwable cause) {
        super(message, cause);
    }

    public TahachiException(Throwable cause) {
        super(cause);
    }

}
