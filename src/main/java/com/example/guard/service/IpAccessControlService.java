package com.example.guard.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Сервис для управления доступом по IP адресам (Blacklist/Whitelist)
 */
@Service
public class IpAccessControlService {

    private static final Logger logger = LoggerFactory.getLogger(IpAccessControlService.class);

    // Черный список IP адресов
    private final Set<String> blacklistedIps = ConcurrentHashMap.newKeySet();
    
    // Белый список IP адресов (если включен, разрешены только эти IP)
    private final Set<String> whitelistedIps = ConcurrentHashMap.newKeySet();
    
    // Счетчики попыток доступа
    private final Map<String, AtomicLong> accessAttempts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> failedAttempts = new ConcurrentHashMap<>();
    
    // Временные блокировки (IP -> время разблокировки)
    private final Map<String, Long> temporaryBlocks = new ConcurrentHashMap<>();
    
    // Настройки
    private boolean whitelistMode = false; // false = blacklist mode, true = whitelist mode
    private int maxFailedAttempts = 5; // Максимум неудачных попыток перед блокировкой
    private long blockDurationMinutes = 60; // Длительность блокировки в минутах

    /**
     * Проверка доступа для IP адреса
     */
    public boolean isAccessAllowed(String ip) {
        // Проверка временной блокировки
        if (isTemporarilyBlocked(ip)) {
            logger.warn("🚫 IP {} временно заблокирован", ip);
            return false;
        }

        // Проверка белого списка (если включен режим whitelist)
        if (whitelistMode) {
            boolean allowed = whitelistedIps.contains(ip);
            if (!allowed) {
                logger.warn("🚫 IP {} не в белом списке", ip);
            }
            return allowed;
        }

        // Проверка черного списка
        boolean blocked = blacklistedIps.contains(ip);
        if (blocked) {
            logger.warn("🚫 IP {} в черном списке", ip);
        }
        
        return !blocked;
    }

    /**
     * Добавление IP в черный список
     */
    public void addToBlacklist(String ip) {
        blacklistedIps.add(ip);
        logger.info("🚫 IP {} добавлен в черный список", ip);
    }

    /**
     * Удаление IP из черного списка
     */
    public void removeFromBlacklist(String ip) {
        blacklistedIps.remove(ip);
        logger.info("✅ IP {} удален из черного списка", ip);
    }

    /**
     * Добавление IP в белый список
     */
    public void addToWhitelist(String ip) {
        whitelistedIps.add(ip);
        logger.info("✅ IP {} добавлен в белый список", ip);
    }

    /**
     * Удаление IP из белого списка
     */
    public void removeFromWhitelist(String ip) {
        whitelistedIps.remove(ip);
        logger.info("❌ IP {} удален из белого списка", ip);
    }

    /**
     * Временная блокировка IP
     */
    public void temporarilyBlockIp(String ip) {
        long blockUntil = System.currentTimeMillis() + (blockDurationMinutes * 60 * 1000);
        temporaryBlocks.put(ip, blockUntil);
        logger.warn("⏰ IP {} временно заблокирован до {}", ip, new Date(blockUntil));
    }

    /**
     * Проверка временной блокировки
     */
    private boolean isTemporarilyBlocked(String ip) {
        Long blockUntil = temporaryBlocks.get(ip);
        if (blockUntil == null) {
            return false;
        }
        
        if (System.currentTimeMillis() > blockUntil) {
            // Время блокировки истекло
            temporaryBlocks.remove(ip);
            return false;
        }
        
        return true;
    }

    /**
     * Регистрация неудачной попытки доступа
     */
    public void recordFailedAttempt(String ip) {
        AtomicLong failedCount = failedAttempts.computeIfAbsent(ip, k -> new AtomicLong(0));
        long count = failedCount.incrementAndGet();
        
        logger.warn("❌ Неудачная попытка доступа от IP {} (попытка #{})", ip, count);
        
        // Автоматическая блокировка при превышении лимита
        if (count >= maxFailedAttempts) {
            temporarilyBlockIp(ip);
            logger.error("🚨 IP {} автоматически заблокирован после {} неудачных попыток", ip, count);
        }
    }

    /**
     * Регистрация успешной попытки доступа
     */
    public void recordSuccessfulAttempt(String ip) {
        accessAttempts.computeIfAbsent(ip, k -> new AtomicLong(0)).incrementAndGet();
        
        // Сброс счетчика неудачных попыток при успешном доступе
        failedAttempts.remove(ip);
        
        logger.debug("✅ Успешный доступ от IP {}", ip);
    }

    /**
     * Получение статистики по IP
     */
    public Map<String, Object> getIpStatistics(String ip) {
        Map<String, Object> stats = new HashMap<>();
        stats.put("ip", ip);
        stats.put("accessAttempts", accessAttempts.getOrDefault(ip, new AtomicLong(0)).get());
        stats.put("failedAttempts", failedAttempts.getOrDefault(ip, new AtomicLong(0)).get());
        stats.put("isBlacklisted", blacklistedIps.contains(ip));
        stats.put("isWhitelisted", whitelistedIps.contains(ip));
        stats.put("isTemporarilyBlocked", isTemporarilyBlocked(ip));
        
        Long blockUntil = temporaryBlocks.get(ip);
        if (blockUntil != null) {
            stats.put("blockedUntil", new Date(blockUntil));
        }
        
        return stats;
    }

    /**
     * Получение всех заблокированных IP
     */
    public Set<String> getBlacklistedIps() {
        return new HashSet<>(blacklistedIps);
    }

    /**
     * Получение всех разрешенных IP
     */
    public Set<String> getWhitelistedIps() {
        return new HashSet<>(whitelistedIps);
    }

    /**
     * Получение временно заблокированных IP
     */
    public Map<String, Date> getTemporarilyBlockedIps() {
        Map<String, Date> blocked = new HashMap<>();
        for (Map.Entry<String, Long> entry : temporaryBlocks.entrySet()) {
            blocked.put(entry.getKey(), new Date(entry.getValue()));
        }
        return blocked;
    }

    /**
     * Очистка истекших временных блокировок
     */
    public void cleanupExpiredBlocks() {
        long now = System.currentTimeMillis();
        temporaryBlocks.entrySet().removeIf(entry -> entry.getValue() < now);
        logger.debug("🧹 Очистка истекших временных блокировок завершена");
    }

    /**
     * Получение топ IP по количеству попыток доступа
     */
    public Map<String, Long> getTopAccessIps(int limit) {
        return accessAttempts.entrySet().stream()
                .sorted(Map.Entry.<String, AtomicLong>comparingByValue((a, b) -> Long.compare(b.get(), a.get())))
                .limit(limit)
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().get()), Map::putAll);
    }

    /**
     * Получение топ IP по количеству неудачных попыток
     */
    public Map<String, Long> getTopFailedIps(int limit) {
        return failedAttempts.entrySet().stream()
                .sorted(Map.Entry.<String, AtomicLong>comparingByValue((a, b) -> Long.compare(b.get(), a.get())))
                .limit(limit)
                .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue().get()), Map::putAll);
    }

    /**
     * Включение/выключение режима белого списка
     */
    public void setWhitelistMode(boolean enabled) {
        this.whitelistMode = enabled;
        logger.info("🔧 Режим белого списка {}", enabled ? "включен" : "выключен");
    }

    /**
     * Установка максимального количества неудачных попыток
     */
    public void setMaxFailedAttempts(int maxAttempts) {
        this.maxFailedAttempts = maxAttempts;
        logger.info("🔧 Максимальное количество неудачных попыток установлено: {}", maxAttempts);
    }

    /**
     * Установка длительности блокировки
     */
    public void setBlockDurationMinutes(long minutes) {
        this.blockDurationMinutes = minutes;
        logger.info("🔧 Длительность блокировки установлена: {} минут", minutes);
    }

    /**
     * Получение текущих настроек
     */
    public Map<String, Object> getSettings() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("whitelistMode", whitelistMode);
        settings.put("maxFailedAttempts", maxFailedAttempts);
        settings.put("blockDurationMinutes", blockDurationMinutes);
        settings.put("blacklistedCount", blacklistedIps.size());
        settings.put("whitelistedCount", whitelistedIps.size());
        settings.put("temporarilyBlockedCount", temporaryBlocks.size());
        return settings;
    }
}
