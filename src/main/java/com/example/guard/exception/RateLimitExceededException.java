package com.example.guard.exception;

public class RateLimitExceededException extends RuntimeException {
    
    private final long retryAfter;
    
    public RateLimitExceededException(String message, long retryAfter) {
        super(message);
        this.retryAfter = retryAfter;
    }
    
    public RateLimitExceededException(String message) {
        super(message);
        this.retryAfter = 60; // По умолчанию 60 секунд
    }
    
    public long getRetryAfter() {
        return retryAfter;
    }
}

