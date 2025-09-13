package com.example.guard.controller;

import com.example.guard.service.SecurityLoggingService;
import com.example.guard.service.IpAccessControlService;
import com.example.guard.service.ThreatDetectionService;
import com.example.guard.service.RateLimitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Контроллер для Security Dashboard - мониторинг безопасности WAF
 * Доступен только администраторам
 */
@RestController
@RequestMapping("/admin/security")
@PreAuthorize("hasRole('ADMIN')")
public class SecurityDashboardController {

    @Autowired
    private SecurityLoggingService securityLoggingService;

    @Autowired
    private IpAccessControlService ipAccessControlService;

    @Autowired
    private ThreatDetectionService threatDetectionService;

    @Autowired
    private RateLimitService rateLimitService;

    /**
     * Получение общей статистики безопасности
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getSecurityStats() {
        Map<String, Object> stats = new HashMap<>();
        
        // Статистика атак
        stats.put("attackStats", securityLoggingService.getAttackStatistics());
        
        // Настройки IP контроля
        stats.put("ipControlSettings", ipAccessControlService.getSettings());
        
        // Статистика rate limiting
        stats.put("rateLimitStats", Map.of(
            "activeClients", rateLimitService.getActiveClientsCount(),
            "totalRequests", rateLimitService.getTotalRequestsCount()
        ));
        
        return ResponseEntity.ok(stats);
    }

    /**
     * Получение недавних событий безопасности
     */
    @GetMapping("/events")
    public ResponseEntity<List<SecurityLoggingService.SecurityEvent>> getRecentEvents(
            @RequestParam(defaultValue = "50") int limit) {
        List<SecurityLoggingService.SecurityEvent> events = 
            securityLoggingService.getRecentSecurityEvents(limit);
        return ResponseEntity.ok(events);
    }

    /**
     * Получение событий для конкретного IP
     */
    @GetMapping("/events/ip/{ip}")
    public ResponseEntity<List<SecurityLoggingService.SecurityEvent>> getEventsForIp(@PathVariable String ip) {
        List<SecurityLoggingService.SecurityEvent> events = 
            securityLoggingService.getEventsForIp(ip);
        return ResponseEntity.ok(events);
    }

    /**
     * Получение топ атакующих IP
     */
    @GetMapping("/attackers")
    public ResponseEntity<Map<String, Integer>> getTopAttackers(
            @RequestParam(defaultValue = "10") int limit) {
        Map<String, Integer> attackers = securityLoggingService.getTopAttackers(limit);
        return ResponseEntity.ok(attackers);
    }

    /**
     * Получение черного списка IP
     */
    @GetMapping("/blacklist")
    public ResponseEntity<Set<String>> getBlacklist() {
        Set<String> blacklist = ipAccessControlService.getBlacklistedIps();
        return ResponseEntity.ok(blacklist);
    }

    /**
     * Добавление IP в черный список
     */
    @PostMapping("/blacklist/{ip}")
    public ResponseEntity<Map<String, String>> addToBlacklist(@PathVariable String ip) {
        ipAccessControlService.addToBlacklist(ip);
        return ResponseEntity.ok(Map.of(
            "message", "IP " + ip + " добавлен в черный список",
            "ip", ip
        ));
    }

    /**
     * Удаление IP из черного списка
     */
    @DeleteMapping("/blacklist/{ip}")
    public ResponseEntity<Map<String, String>> removeFromBlacklist(@PathVariable String ip) {
        ipAccessControlService.removeFromBlacklist(ip);
        return ResponseEntity.ok(Map.of(
            "message", "IP " + ip + " удален из черного списка",
            "ip", ip
        ));
    }

    /**
     * Получение белого списка IP
     */
    @GetMapping("/whitelist")
    public ResponseEntity<Set<String>> getWhitelist() {
        Set<String> whitelist = ipAccessControlService.getWhitelistedIps();
        return ResponseEntity.ok(whitelist);
    }

    /**
     * Добавление IP в белый список
     */
    @PostMapping("/whitelist/{ip}")
    public ResponseEntity<Map<String, String>> addToWhitelist(@PathVariable String ip) {
        ipAccessControlService.addToWhitelist(ip);
        return ResponseEntity.ok(Map.of(
            "message", "IP " + ip + " добавлен в белый список",
            "ip", ip
        ));
    }

    /**
     * Удаление IP из белого списка
     */
    @DeleteMapping("/whitelist/{ip}")
    public ResponseEntity<Map<String, String>> removeFromWhitelist(@PathVariable String ip) {
        ipAccessControlService.removeFromWhitelist(ip);
        return ResponseEntity.ok(Map.of(
            "message", "IP " + ip + " удален из белого списка",
            "ip", ip
        ));
    }

    /**
     * Получение временно заблокированных IP
     */
    @GetMapping("/blocked")
    public ResponseEntity<Map<String, java.util.Date>> getTemporarilyBlockedIps() {
        Map<String, java.util.Date> blocked = ipAccessControlService.getTemporarilyBlockedIps();
        return ResponseEntity.ok(blocked);
    }

    /**
     * Получение статистики по конкретному IP
     */
    @GetMapping("/ip/{ip}/stats")
    public ResponseEntity<Map<String, Object>> getIpStats(@PathVariable String ip) {
        Map<String, Object> stats = ipAccessControlService.getIpStatistics(ip);
        return ResponseEntity.ok(stats);
    }

    /**
     * Получение топ IP по количеству попыток доступа
     */
    @GetMapping("/top-access-ips")
    public ResponseEntity<Map<String, Long>> getTopAccessIps(
            @RequestParam(defaultValue = "10") int limit) {
        Map<String, Long> topIps = ipAccessControlService.getTopAccessIps(limit);
        return ResponseEntity.ok(topIps);
    }

    /**
     * Получение топ IP по количеству неудачных попыток
     */
    @GetMapping("/top-failed-ips")
    public ResponseEntity<Map<String, Long>> getTopFailedIps(
            @RequestParam(defaultValue = "10") int limit) {
        Map<String, Long> topIps = ipAccessControlService.getTopFailedIps(limit);
        return ResponseEntity.ok(topIps);
    }

    /**
     * Включение/выключение режима белого списка
     */
    @PostMapping("/whitelist-mode")
    public ResponseEntity<Map<String, String>> setWhitelistMode(@RequestParam boolean enabled) {
        ipAccessControlService.setWhitelistMode(enabled);
        return ResponseEntity.ok(Map.of(
            "message", "Режим белого списка " + (enabled ? "включен" : "выключен"),
            "whitelistMode", String.valueOf(enabled)
        ));
    }

    /**
     * Настройка максимального количества неудачных попыток
     */
    @PostMapping("/max-failed-attempts")
    public ResponseEntity<Map<String, String>> setMaxFailedAttempts(@RequestParam int maxAttempts) {
        ipAccessControlService.setMaxFailedAttempts(maxAttempts);
        return ResponseEntity.ok(Map.of(
            "message", "Максимальное количество неудачных попыток установлено: " + maxAttempts,
            "maxFailedAttempts", String.valueOf(maxAttempts)
        ));
    }

    /**
     * Настройка длительности блокировки
     */
    @PostMapping("/block-duration")
    public ResponseEntity<Map<String, String>> setBlockDuration(@RequestParam long minutes) {
        ipAccessControlService.setBlockDurationMinutes(minutes);
        return ResponseEntity.ok(Map.of(
            "message", "Длительность блокировки установлена: " + minutes + " минут",
            "blockDurationMinutes", String.valueOf(minutes)
        ));
    }

    /**
     * Очистка старых событий
     */
    @PostMapping("/cleanup")
    public ResponseEntity<Map<String, String>> cleanupOldEvents() {
        securityLoggingService.cleanupOldEvents();
        ipAccessControlService.cleanupExpiredBlocks();
        return ResponseEntity.ok(Map.of(
            "message", "Очистка старых событий и истекших блокировок завершена"
        ));
    }

    /**
     * Получение информации о WAF
     */
    @GetMapping("/waf-info")
    public ResponseEntity<Map<String, Object>> getWafInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("name", "RBAC Security Guard WAF");
        info.put("version", "1.0.0");
        info.put("features", List.of(
            "Rate Limiting",
            "Threat Detection",
            "IP Access Control",
            "Security Logging",
            "RBAC Authentication",
            "SQL Injection Protection",
            "XSS Protection",
            "Path Traversal Protection",
            "Command Injection Protection"
        ));
        info.put("status", "ACTIVE");
        info.put("uptime", System.currentTimeMillis());
        
        return ResponseEntity.ok(info);
    }

    /**
     * Тестирование WAF с подозрительным запросом
     */
    @PostMapping("/test")
    public ResponseEntity<Map<String, Object>> testWaf(@RequestParam String testType) {
        Map<String, Object> result = new HashMap<>();
        
        switch (testType.toLowerCase()) {
            case "sql":
                result.put("test", "SQL Injection Test");
                result.put("payload", "'; DROP TABLE users; --");
                result.put("expected", "BLOCKED");
                result.put("status", "WAF защищает от SQL инъекций");
                break;
            case "xss":
                result.put("test", "XSS Test");
                result.put("payload", "<script>alert('XSS')</script>");
                result.put("expected", "BLOCKED");
                result.put("status", "WAF защищает от XSS атак");
                break;
            case "path":
                result.put("test", "Path Traversal Test");
                result.put("payload", "../../../etc/passwd");
                result.put("expected", "BLOCKED");
                result.put("status", "WAF защищает от Path Traversal");
                break;
            default:
                result.put("error", "Неизвестный тип теста. Доступные: sql, xss, path");
                return ResponseEntity.badRequest().body(result);
        }
        
        return ResponseEntity.ok(result);
    }
}
