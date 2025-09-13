package com.example.guard.controller;

import com.example.guard.dto.UserDto;
import com.example.guard.entity.Role;
import com.example.guard.service.RateLimitService;
import com.example.guard.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private RateLimitService rateLimitService;
    
    /**
     * Получает всех пользователей
     */
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        List<UserDto> users = userService.getAllUsers();
        
        Map<String, Object> response = new HashMap<>();
        response.put("users", users);
        response.put("totalCount", users.size());
        response.put("admin", authentication.getName());
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Получает пользователей по роли
     */
    @GetMapping("/users/role/{role}")
    public ResponseEntity<?> getUsersByRole(@PathVariable String role, 
                                           Authentication authentication, 
                                           HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        try {
            Role roleEnum = Role.valueOf(role.toUpperCase());
            List<UserDto> users = userService.getUsersByRole(roleEnum);
            
            Map<String, Object> response = new HashMap<>();
            response.put("users", users);
            response.put("role", role);
            response.put("count", users.size());
            response.put("admin", authentication.getName());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Invalid role");
            error.put("message", "Role must be ADMIN or USER");
            return ResponseEntity.badRequest().body(error);
        }
    }
    
    /**
     * Удаляет пользователя
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id, 
                                       Authentication authentication, 
                                       HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        try {
            userService.deleteUser(id);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User deleted successfully");
            response.put("deletedUserId", id);
            response.put("admin", authentication.getName());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "User not found");
            error.put("message", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }
    
    /**
     * Блокирует/разблокирует пользователя
     */
    @PutMapping("/users/{id}/toggle-status")
    public ResponseEntity<?> toggleUserStatus(@PathVariable Long id, 
                                             Authentication authentication, 
                                             HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        try {
            userService.toggleUserStatus(id);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User status toggled successfully");
            response.put("userId", id);
            response.put("admin", authentication.getName());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "User not found");
            error.put("message", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }
    
    /**
     * Получает информацию о системе
     */
    @GetMapping("/system")
    public ResponseEntity<?> getSystemInfo(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        UserService.UserStats stats = userService.getUserStats();
        
        Map<String, Object> systemInfo = new HashMap<>();
        systemInfo.put("systemStatus", "UP");
        systemInfo.put("version", "1.0.0");
        systemInfo.put("userStats", stats);
        systemInfo.put("rateLimitConfig", Map.of(
            "maxRequests", 10,
            "windowDuration", "1 minute"
        ));
        systemInfo.put("admin", authentication.getName());
        systemInfo.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(systemInfo);
    }
    
    /**
     * Получает статистику безопасности
     */
    @GetMapping("/security-stats")
    public ResponseEntity<?> getSecurityStats(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        Map<String, Object> securityStats = new HashMap<>();
        securityStats.put("authenticationMethod", "Basic Authentication");
        securityStats.put("authorizationMethod", "Role-Based Access Control (RBAC)");
        securityStats.put("rateLimitingEnabled", true);
        securityStats.put("ddosProtectionEnabled", true);
        securityStats.put("maxRequestsPerMinute", 10);
        securityStats.put("admin", authentication.getName());
        securityStats.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(securityStats);
    }
    
    /**
     * Извлекает идентификатор клиента из запроса
     */
    private String getClientId(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}

