package com.example.guard.dto;

import com.example.guard.entity.Role;

public class LoginResponse {
    
    private String username;
    private Role role;
    private String message;
    private boolean success;
    
    // Constructors
    public LoginResponse() {}
    
    public LoginResponse(String username, Role role, String message, boolean success) {
        this.username = username;
        this.role = role;
        this.message = message;
        this.success = success;
    }
    
    // Static factory methods
    public static LoginResponse success(String username, Role role) {
        return new LoginResponse(username, role, "Login successful", true);
    }
    
    public static LoginResponse failure(String message) {
        return new LoginResponse(null, null, message, false);
    }
    
    // Getters and Setters
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public Role getRole() {
        return role;
    }
    
    public void setRole(Role role) {
        this.role = role;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    @Override
    public String toString() {
        return "LoginResponse{" +
                "username='" + username + '\'' +
                ", role=" + role +
                ", message='" + message + '\'' +
                ", success=" + success +
                '}';
    }
}

