package com.example.guard.security;

import com.example.guard.service.ThreatDetectionService;
import com.example.guard.service.SecurityLoggingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Security Filter для анализа HTTP запросов и обнаружения угроз
 * Это основной компонент Web Application Firewall (WAF)
 */
@Component
@Order(1) // Выполняется первым в цепочке фильтров
public class SecurityFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SecurityFilter.class);

    @Autowired
    private ThreatDetectionService threatDetectionService;

    @Autowired
    private SecurityLoggingService securityLoggingService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String requestUri = request.getRequestURI();
        String method = request.getMethod();
        
        logger.debug("🔍 WAF: Анализ запроса {} {} от IP: {}", method, requestUri, clientIp);

        try {
            // 1. Проверка на известные угрозы
            ThreatDetectionService.ThreatLevel threatLevel = threatDetectionService.analyzeRequest(request);
            
            if (threatLevel == ThreatDetectionService.ThreatLevel.HIGH || 
                threatLevel == ThreatDetectionService.ThreatLevel.MEDIUM) {
                
                String threatType = threatLevel == ThreatDetectionService.ThreatLevel.HIGH ? 
                    "HIGH_THREAT_DETECTED" : "MEDIUM_THREAT_DETECTED";
                String description = threatLevel == ThreatDetectionService.ThreatLevel.HIGH ? 
                    "Высокая угроза обнаружена" : "Средняя угроза обнаружена";
                
                logger.warn("🚨 WAF: Обнаружена {} угроза от IP: {} - URI: {}", 
                    threatLevel == ThreatDetectionService.ThreatLevel.HIGH ? "высокая" : "средняя", 
                    clientIp, requestUri);
                securityLoggingService.logThreat(request, threatType, description);
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("{\"error\":\"Access denied by security policy\"}");
                return;
            }

            // 2. Добавление security headers
            addSecurityHeaders(response);

            // 3. Логирование запроса
            securityLoggingService.logRequest(request, threatLevel);

            // Продолжаем обработку запроса
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("❌ WAF: Ошибка при анализе запроса от IP: {}", clientIp, e);
            securityLoggingService.logThreat(request, "FILTER_ERROR", "Ошибка в security filter: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"Security analysis failed\"}");
        }
    }

    /**
     * Добавление security headers для защиты от различных атак
     */
    private void addSecurityHeaders(HttpServletResponse response) {
        // Защита от XSS
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        // X-Frame-Options - только если не установлен Spring Security
        if (response.getHeader("X-Frame-Options") == null) {
            response.setHeader("X-Frame-Options", "DENY");
        }
        
        response.setHeader("X-XSS-Protection", "1; mode=block");
        
        // Content Security Policy
        response.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'");
        
        // Защита от MIME sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        // Referrer Policy
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Permissions Policy
        response.setHeader("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()");
        
        // Strict Transport Security (для HTTPS)
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        
        logger.debug("🛡️ WAF: Добавлены security headers");
    }

    /**
     * Получение реального IP адреса клиента
     */
    private String getClientIpAddress(HttpServletRequest request) {
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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Не фильтруем статические ресурсы и health checks
        String path = request.getRequestURI();
        
        // Проверка на слишком длинный URI (более 2048 символов)
        if (path.length() > 2048) {
            logger.warn("🚨 WAF: Слишком длинный URI: {} символов", path.length());
            return false; // Фильтруем, чтобы заблокировать
        }
        
        return path.startsWith("/static/") || 
               path.startsWith("/css/") || 
               path.startsWith("/js/") || 
               path.startsWith("/images/") ||
               path.equals("/actuator/health");
    }
}
