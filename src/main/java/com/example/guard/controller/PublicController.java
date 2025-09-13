package com.example.guard.controller;

import com.example.guard.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/public")
public class PublicController {
    
    @Autowired
    private RateLimitService rateLimitService;
    
    /**
     * Получает публичную информацию
     */
    @GetMapping("/info")
    public ResponseEntity<?> getPublicInfo(HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        Map<String, Object> info = new HashMap<>();
        info.put("message", "Welcome to RBAC Security Guard");
        info.put("description", "This is a public endpoint accessible to everyone");
        info.put("timestamp", LocalDateTime.now());
        info.put("version", "1.0.0");
        
        return ResponseEntity.ok(info);
    }
    
    /**
     * Получает статус системы
     */
    @GetMapping("/status")
    public ResponseEntity<?> getSystemStatus(HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("message", "System is running normally");
        status.put("timestamp", LocalDateTime.now());
        status.put("uptime", "System is operational");
        
        return ResponseEntity.ok(status);
    }
    
    /**
     * Получает информацию о rate limiting
     */
    @GetMapping("/rate-limit-info")
    public ResponseEntity<?> getRateLimitInfo(HttpServletRequest request) {
        String clientId = getClientId(request);
        
        Map<String, Object> info = new HashMap<>();
        info.put("clientId", clientId);
        info.put("remainingRequests", rateLimitService.getRemainingRequests(clientId));
        info.put("timeUntilReset", rateLimitService.getTimeUntilReset(clientId));
        info.put("maxRequests", 10);
        info.put("windowDuration", "1 minute");
        
        return ResponseEntity.ok(info);
    }
    
    /**
     * Получает информацию о системе безопасности
     */
    @GetMapping("/security-info")
    public ResponseEntity<?> getSecurityInfo(HttpServletRequest request) {
        String clientId = getClientId(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Rate limit exceeded");
            response.put("message", "Too many requests. Please try again later.");
            response.put("retryAfter", rateLimitService.getTimeUntilReset(clientId));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }
        
        Map<String, Object> securityInfo = new HashMap<>();
        securityInfo.put("authentication", "Basic Authentication");
        securityInfo.put("authorization", "Role-Based Access Control (RBAC)");
        securityInfo.put("roles", new String[]{"ADMIN", "USER"});
        securityInfo.put("rateLimiting", "Enabled (10 requests per minute)");
        securityInfo.put("ddosProtection", "Enabled");
        
        return ResponseEntity.ok(securityInfo);
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

