package com.example.guard.dto;

import com.example.guard.entity.Role;

import java.time.LocalDateTime;

public class UserDto {
    
    private Long id;
    private String username;
    private Role role;
    private boolean enabled;
    private LocalDateTime lastLogin;
    private int loginAttempts;
    private LocalDateTime lockedUntil;
    
    // Constructors
    public UserDto() {}
    
    public UserDto(Long id, String username, Role role, boolean enabled, 
                   LocalDateTime lastLogin, int loginAttempts, LocalDateTime lockedUntil) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.enabled = enabled;
        this.lastLogin = lastLogin;
        this.loginAttempts = loginAttempts;
        this.lockedUntil = lockedUntil;
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
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
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public LocalDateTime getLastLogin() {
        return lastLogin;
    }
    
    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }
    
    public int getLoginAttempts() {
        return loginAttempts;
    }
    
    public void setLoginAttempts(int loginAttempts) {
        this.loginAttempts = loginAttempts;
    }
    
    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }
    
    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }
    
    @Override
    public String toString() {
        return "UserDto{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", role=" + role +
                ", enabled=" + enabled +
                ", lastLogin=" + lastLogin +
                ", loginAttempts=" + loginAttempts +
                ", lockedUntil=" + lockedUntil +
                '}';
    }
}

