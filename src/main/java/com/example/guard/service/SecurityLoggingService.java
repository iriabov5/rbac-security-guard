package com.example.guard.service;

import com.example.guard.service.ThreatDetectionService.ThreatLevel;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Сервис для логирования событий безопасности и мониторинга атак
 */
@Service
public class SecurityLoggingService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityLoggingService.class);
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    // Хранение статистики атак
    private final Map<String, AtomicLong> attackCounts = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityEvent>> recentEvents = new ConcurrentHashMap<>();
    private final AtomicLong totalThreats = new AtomicLong(0);
    private final AtomicLong totalRequests = new AtomicLong(0);

    /**
     * Логирование HTTP запроса
     */
    public void logRequest(HttpServletRequest request, ThreatLevel threatLevel) {
        totalRequests.incrementAndGet();
        
        String clientIp = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String uri = request.getRequestURI();
        String method = request.getMethod();
        
        // Создание события безопасности
        SecurityEvent event = new SecurityEvent(
            LocalDateTime.now(),
            clientIp,
            method,
            uri,
            userAgent,
            threatLevel,
            "REQUEST",
            "HTTP запрос обработан"
        );

        // Логирование в зависимости от уровня угрозы
        switch (threatLevel) {
            case HIGH, CRITICAL:
                securityLogger.warn("🚨 ВЫСОКИЙ УРОВЕНЬ УГРОЗЫ: {} {} от IP: {} - User-Agent: {}", 
                    method, uri, clientIp, userAgent);
                logSecurityEvent(event);
                break;
            case MEDIUM:
                securityLogger.info("⚠️ СРЕДНИЙ УРОВЕНЬ УГРОЗЫ: {} {} от IP: {} - User-Agent: {}", 
                    method, uri, clientIp, userAgent);
                logSecurityEvent(event);
                break;
            case LOW:
                logger.debug("🔍 Запрос: {} {} от IP: {}", method, uri, clientIp);
                break;
        }
    }

    /**
     * Логирование обнаруженной угрозы
     */
    public void logThreat(HttpServletRequest request, String threatType, String description) {
        totalThreats.incrementAndGet();
        attackCounts.computeIfAbsent(threatType, k -> new AtomicLong(0)).incrementAndGet();
        
        String clientIp = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String uri = request.getRequestURI();
        String method = request.getMethod();
        
        // Создание события безопасности
        SecurityEvent event = new SecurityEvent(
            LocalDateTime.now(),
            clientIp,
            method,
            uri,
            userAgent,
            ThreatLevel.HIGH,
            threatType,
            description
        );

        // Критическое логирование
        securityLogger.error("🚨 УГРОЗА ОБНАРУЖЕНА: {} - {} {} от IP: {} - User-Agent: {} - Описание: {}", 
            threatType, method, uri, clientIp, userAgent, description);

        logSecurityEvent(event);
    }

    /**
     * Логирование события безопасности
     */
    private void logSecurityEvent(SecurityEvent event) {
        String clientIp = event.getClientIp();
        
        // Добавление события в список недавних событий
        recentEvents.computeIfAbsent(clientIp, k -> new ArrayList<>()).add(event);
        
        // Ограничение размера списка (храним только последние 100 событий на IP)
        List<SecurityEvent> events = recentEvents.get(clientIp);
        if (events.size() > 100) {
            events.remove(0);
        }

        // Детальное логирование в JSON формате
        securityLogger.info("SECURITY_EVENT: {}", event.toJson());
    }

    /**
     * Получение статистики атак
     */
    public Map<String, Object> getAttackStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalRequests", totalRequests.get());
        stats.put("totalThreats", totalThreats.get());
        stats.put("threatRate", totalRequests.get() > 0 ? 
            (double) totalThreats.get() / totalRequests.get() * 100 : 0);
        stats.put("attackCounts", new HashMap<>(attackCounts));
        stats.put("uniqueAttackers", recentEvents.size());
        stats.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        
        return stats;
    }

    /**
     * Получение недавних событий безопасности
     */
    public List<SecurityEvent> getRecentSecurityEvents(int limit) {
        List<SecurityEvent> allEvents = new ArrayList<>();
        
        for (List<SecurityEvent> events : recentEvents.values()) {
            allEvents.addAll(events);
        }
        
        // Сортировка по времени (новые сначала)
        allEvents.sort((e1, e2) -> e2.getTimestamp().compareTo(e1.getTimestamp()));
        
        return allEvents.stream()
                .limit(limit)
                .toList();
    }

    /**
     * Получение событий для конкретного IP
     */
    public List<SecurityEvent> getEventsForIp(String ip) {
        return recentEvents.getOrDefault(ip, new ArrayList<>());
    }

    /**
     * Получение топ атакующих IP
     */
    public Map<String, Integer> getTopAttackers(int limit) {
        Map<String, Integer> attackerCounts = new HashMap<>();
        
        for (Map.Entry<String, List<SecurityEvent>> entry : recentEvents.entrySet()) {
            String ip = entry.getKey();
            long threatCount = entry.getValue().stream()
                    .filter(e -> e.getThreatLevel() != ThreatLevel.LOW)
                    .count();
            
            if (threatCount > 0) {
                attackerCounts.put(ip, (int) threatCount);
            }
        }
        
        return attackerCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(limit)
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
    }

    /**
     * Очистка старых событий (старше 24 часов)
     */
    public void cleanupOldEvents() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        
        for (Map.Entry<String, List<SecurityEvent>> entry : recentEvents.entrySet()) {
            List<SecurityEvent> events = entry.getValue();
            events.removeIf(event -> event.getTimestamp().isBefore(cutoff));
            
            if (events.isEmpty()) {
                recentEvents.remove(entry.getKey());
            }
        }
        
        logger.info("🧹 Очистка старых событий безопасности завершена");
    }

    /**
     * Получение IP адреса клиента
     */
    private String getClientIp(HttpServletRequest request) {
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

    /**
     * Класс для представления события безопасности
     */
    public static class SecurityEvent {
        private final LocalDateTime timestamp;
        private final String clientIp;
        private final String method;
        private final String uri;
        private final String userAgent;
        private final ThreatLevel threatLevel;
        private final String eventType;
        private final String description;

        public SecurityEvent(LocalDateTime timestamp, String clientIp, String method, 
                           String uri, String userAgent, ThreatLevel threatLevel, 
                           String eventType, String description) {
            this.timestamp = timestamp;
            this.clientIp = clientIp;
            this.method = method;
            this.uri = uri;
            this.userAgent = userAgent;
            this.threatLevel = threatLevel;
            this.eventType = eventType;
            this.description = description;
        }

        // Getters
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getClientIp() { return clientIp; }
        public String getMethod() { return method; }
        public String getUri() { return uri; }
        public String getUserAgent() { return userAgent; }
        public ThreatLevel getThreatLevel() { return threatLevel; }
        public String getEventType() { return eventType; }
        public String getDescription() { return description; }

        /**
         * Преобразование в JSON строку
         */
        public String toJson() {
            return String.format(
                "{\"timestamp\":\"%s\",\"clientIp\":\"%s\",\"method\":\"%s\",\"uri\":\"%s\"," +
                "\"userAgent\":\"%s\",\"threatLevel\":\"%s\",\"eventType\":\"%s\",\"description\":\"%s\"}",
                timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                clientIp, method, uri, userAgent, threatLevel, eventType, description
            );
        }
    }
}
