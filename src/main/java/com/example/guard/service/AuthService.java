package com.example.guard.service;

import com.example.guard.dto.LoginRequest;
import com.example.guard.dto.LoginResponse;
import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuthService {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    /**
     * Аутентифицирует пользователя
     */
    public LoginResponse authenticate(LoginRequest loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();
        
        // Проверяем существование пользователя
        User user = userService.findByUsername(username)
                .orElse(null);
        
        if (user == null) {
            return LoginResponse.failure("Invalid username or password");
        }
        
        // Проверяем, не заблокирован ли аккаунт
        if (!user.isAccountNonLocked()) {
            return LoginResponse.failure("Account is locked. Try again later.");
        }
        
        // Проверяем, активен ли аккаунт
        if (!user.isEnabled()) {
            return LoginResponse.failure("Account is disabled");
        }
        
        // Проверяем пароль
        if (!passwordEncoder.matches(password, user.getPassword())) {
            userService.incrementLoginAttempts(username);
            return LoginResponse.failure("Invalid username or password");
        }
        
        // Успешная аутентификация
        userService.updateLastLogin(username);
        return LoginResponse.success(username, user.getRole());
    }
    
    /**
     * Проверяет, может ли пользователь выполнить действие
     */
    public boolean hasPermission(String username, String requiredRole) {
        User user = userService.findByUsername(username)
                .orElse(null);
        
        if (user == null || !user.isEnabled()) {
            return false;
        }
        
        // Проверяем роль
        if ("ADMIN".equals(requiredRole)) {
            return user.getRole() == Role.ADMIN;
        } else if ("USER".equals(requiredRole)) {
            return user.getRole() == Role.USER || user.getRole() == Role.ADMIN;
        }
        
        return false;
    }
    
    /**
     * Получает информацию о пользователе
     */
    public User getUserInfo(String username) {
        return userService.findByUsername(username)
                .orElse(null);
    }
    
    /**
     * Проверяет, является ли пользователь администратором
     */
    public boolean isAdmin(String username) {
        User user = getUserInfo(username);
        return user != null && user.getRole() == Role.ADMIN;
    }
    
    /**
     * Проверяет, является ли пользователь обычным пользователем
     */
    public boolean isUser(String username) {
        User user = getUserInfo(username);
        return user != null && user.getRole() == Role.USER;
    }
}

