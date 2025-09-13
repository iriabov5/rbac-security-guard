package com.example.guard.service;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitService {
    
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastReset = new ConcurrentHashMap<>();
    
    private static final int MAX_REQUESTS = 10; // 10 запросов
    private static final Duration WINDOW = Duration.ofMinutes(1); // в минуту
    
    /**
     * Проверяет, разрешен ли запрос для данного клиента
     * @param clientId идентификатор клиента (IP адрес)
     * @return true если запрос разрешен, false если превышен лимит
     */
    public boolean isAllowed(String clientId) {
        LocalDateTime now = LocalDateTime.now();
        String key = clientId + ":" + now.truncatedTo(ChronoUnit.MINUTES);
        
        AtomicInteger count = requestCounts.computeIfAbsent(key, k -> new AtomicInteger(0));
        LocalDateTime lastResetTime = lastReset.computeIfAbsent(key, k -> now);
        
        // Если прошло больше минуты, сбрасываем счетчик
        if (Duration.between(lastResetTime, now).compareTo(WINDOW) > 0) {
            count.set(0);
            lastReset.put(key, now);
        }
        
        // Проверяем, не превышен ли лимит
        return count.incrementAndGet() <= MAX_REQUESTS;
    }
    
    /**
     * Получает количество оставшихся запросов для клиента
     * @param clientId идентификатор клиента
     * @return количество оставшихся запросов
     */
    public int getRemainingRequests(String clientId) {
        LocalDateTime now = LocalDateTime.now();
        String key = clientId + ":" + now.truncatedTo(ChronoUnit.MINUTES);
        
        AtomicInteger count = requestCounts.get(key);
        if (count == null) {
            return MAX_REQUESTS;
        }
        
        int currentCount = count.get();
        return Math.max(0, MAX_REQUESTS - currentCount);
    }
    
    /**
     * Получает время до сброса лимита
     * @param clientId идентификатор клиента
     * @return время до сброса в секундах
     */
    public long getTimeUntilReset(String clientId) {
        LocalDateTime now = LocalDateTime.now();
        String key = clientId + ":" + now.truncatedTo(ChronoUnit.MINUTES);
        
        LocalDateTime lastResetTime = lastReset.get(key);
        if (lastResetTime == null) {
            return 0;
        }
        
        LocalDateTime nextReset = lastResetTime.plus(WINDOW);
        return Duration.between(now, nextReset).getSeconds();
    }
    
    /**
     * Очищает старые записи для экономии памяти
     */
    public void cleanup() {
        LocalDateTime cutoff = LocalDateTime.now().minus(WINDOW.multipliedBy(2));
        
        requestCounts.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            String[] parts = key.split(":");
            if (parts.length >= 2) {
                try {
                    LocalDateTime keyTime = LocalDateTime.parse(parts[1]);
                    return keyTime.isBefore(cutoff);
                } catch (Exception e) {
                    return true; // Удаляем некорректные записи
                }
            }
            return true;
        });
        
        lastReset.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
    }
}

