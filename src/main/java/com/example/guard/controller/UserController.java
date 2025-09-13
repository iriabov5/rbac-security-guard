package com.example.guard.controller;

import com.example.guard.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
public class UserController {
    
    @Autowired
    private RateLimitService rateLimitService;
    
    /**
     * Получает профиль пользователя
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        String username = authentication.getName();
        
        Map<String, Object> profile = new HashMap<>();
        profile.put("username", username);
        profile.put("authorities", authentication.getAuthorities());
        profile.put("authenticated", authentication.isAuthenticated());
        profile.put("timestamp", LocalDateTime.now());
        profile.put("message", "User profile information");
        
        return ResponseEntity.ok(profile);
    }
    
    /**
     * Получает дашборд пользователя
     */
    @GetMapping("/dashboard")
    public ResponseEntity<?> getUserDashboard(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        String username = authentication.getName();
        
        Map<String, Object> dashboard = new HashMap<>();
        dashboard.put("username", username);
        dashboard.put("welcomeMessage", "Welcome to your dashboard, " + username + "!");
        dashboard.put("availableActions", new String[]{
            "View Profile",
            "Update Settings",
            "View Notifications"
        });
        dashboard.put("timestamp", LocalDateTime.now());
        dashboard.put("userRole", authentication.getAuthorities());
        
        return ResponseEntity.ok(dashboard);
    }
    
    /**
     * Получает настройки пользователя
     */
    @GetMapping("/settings")
    public ResponseEntity<?> getUserSettings(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        String username = authentication.getName();
        
        Map<String, Object> settings = new HashMap<>();
        settings.put("username", username);
        settings.put("notifications", true);
        settings.put("theme", "light");
        settings.put("language", "en");
        settings.put("timezone", "UTC");
        settings.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(settings);
    }
    
    /**
     * Обновляет настройки пользователя
     */
    @PutMapping("/settings")
    public ResponseEntity<?> updateUserSettings(@RequestBody Map<String, Object> settings, 
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
        
        String username = authentication.getName();
        
        Map<String, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("message", "Settings updated successfully");
        response.put("updatedSettings", settings);
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Получает уведомления пользователя
     */
    @GetMapping("/notifications")
    public ResponseEntity<?> getUserNotifications(Authentication authentication, HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        String username = authentication.getName();
        
        Map<String, Object> notifications = new HashMap<>();
        notifications.put("username", username);
        notifications.put("notifications", new String[]{
            "Welcome to the system!",
            "Your account is active",
            "System maintenance scheduled for tomorrow"
        });
        notifications.put("unreadCount", 3);
        notifications.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(notifications);
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

