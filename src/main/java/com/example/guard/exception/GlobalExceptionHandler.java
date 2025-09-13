package com.example.guard.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimitExceeded(
            RateLimitExceededException ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Rate Limit Exceeded");
        response.put("message", ex.getMessage());
        response.put("retryAfter", ex.getRetryAfter());
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }
    
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Authentication Failed");
        response.put("message", "Invalid credentials");
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
    
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Bad Credentials");
        response.put("message", "Invalid username or password");
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Access Denied");
        response.put("message", "You don't have permission to access this resource");
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }
    
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Bad Request");
        response.put("message", ex.getMessage());
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(
            Exception ex, WebRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Internal Server Error");
        response.put("message", "An unexpected error occurred");
        response.put("timestamp", LocalDateTime.now());
        response.put("path", request.getDescription(false).replace("uri=", ""));
        
        // В production не следует показывать детали ошибки
        if (request.getDescription(false).contains("localhost")) {
            response.put("details", ex.getMessage());
        }
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}

