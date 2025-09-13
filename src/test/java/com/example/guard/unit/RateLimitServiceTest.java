package com.example.guard.unit;

import com.example.guard.service.RateLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitServiceTest {
    
    private RateLimitService rateLimitService;
    
    @BeforeEach
    void setUp() {
        rateLimitService = new RateLimitService();
    }
    
    @Test
    void testIsAllowed_WithinLimit() {
        // Given
        String clientId = "192.168.1.100";
        
        // When & Then
        for (int i = 0; i < 10; i++) {
            assertThat(rateLimitService.isAllowed(clientId)).isTrue();
        }
    }
    
    @Test
    void testIsAllowed_ExceedsLimit() {
        // Given
        String clientId = "192.168.1.101";
        
        // When - исчерпываем лимит
        for (int i = 0; i < 10; i++) {
            assertThat(rateLimitService.isAllowed(clientId)).isTrue();
        }
        
        // Then - 11-й запрос должен быть заблокирован
        assertThat(rateLimitService.isAllowed(clientId)).isFalse();
    }
    
    @Test
    void testIsAllowed_DifferentClients() {
        // Given
        String clientId1 = "192.168.1.200";
        String clientId2 = "192.168.1.201";
        
        // When - исчерпываем лимит для первого клиента
        for (int i = 0; i < 10; i++) {
            assertThat(rateLimitService.isAllowed(clientId1)).isTrue();
        }
        
        // Then - первый клиент заблокирован, второй может делать запросы
        assertThat(rateLimitService.isAllowed(clientId1)).isFalse();
        assertThat(rateLimitService.isAllowed(clientId2)).isTrue();
    }
    
    @Test
    void testGetRemainingRequests() {
        // Given
        String clientId = "192.168.1.300";
        
        // When - делаем несколько запросов
        rateLimitService.isAllowed(clientId);
        rateLimitService.isAllowed(clientId);
        rateLimitService.isAllowed(clientId);
        
        // Then
        int remaining = rateLimitService.getRemainingRequests(clientId);
        assertThat(remaining).isEqualTo(7); // 10 - 3 = 7
    }
    
    @Test
    void testGetRemainingRequests_Exceeded() {
        // Given
        String clientId = "192.168.1.301";
        
        // When - исчерпываем лимит
        for (int i = 0; i < 10; i++) {
            rateLimitService.isAllowed(clientId);
        }
        
        // Then
        int remaining = rateLimitService.getRemainingRequests(clientId);
        assertThat(remaining).isEqualTo(0);
    }
    
    @Test
    void testGetRemainingRequests_NewClient() {
        // Given
        String clientId = "192.168.1.302";
        
        // When
        int remaining = rateLimitService.getRemainingRequests(clientId);
        
        // Then
        assertThat(remaining).isEqualTo(10);
    }
    
    @Test
    void testGetTimeUntilReset() {
        // Given
        String clientId = "192.168.1.400";
        
        // When
        long timeUntilReset = rateLimitService.getTimeUntilReset(clientId);
        
        // Then
        assertThat(timeUntilReset).isGreaterThanOrEqualTo(0);
        assertThat(timeUntilReset).isLessThanOrEqualTo(60); // Максимум 60 секунд
    }
    
    @Test
    void testCleanup() {
        // Given
        String clientId = "192.168.1.500";
        
        // When - делаем запросы
        rateLimitService.isAllowed(clientId);
        
        // Then - очистка не должна вызывать исключений
        // Очистка не должна вызывать исключений
        rateLimitService.cleanup();
    }
    
    @Test
    void testConcurrentRequests() throws InterruptedException {
        // Given
        String clientId = "192.168.1.600";
        int numberOfThreads = 20;
        int requestsPerThread = 1;
        
        // When - отправляем одновременные запросы
        Thread[] threads = new Thread[numberOfThreads];
        boolean[] results = new boolean[numberOfThreads];
        
        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < requestsPerThread; j++) {
                    results[index] = rateLimitService.isAllowed(clientId);
                }
            });
        }
        
        // Запускаем все потоки
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Ждем завершения всех потоков
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Then - не более 10 запросов должны пройти успешно
        int successCount = 0;
        for (boolean result : results) {
            if (result) {
                successCount++;
            }
        }
        
        assertThat(successCount).isLessThanOrEqualTo(10);
    }
    
    @Test
    void testRateLimitResetAfterTimeWindow() throws InterruptedException {
        // Given
        String clientId = "192.168.1.700";
        
        // When - исчерпываем лимит
        for (int i = 0; i < 10; i++) {
            assertThat(rateLimitService.isAllowed(clientId)).isTrue();
        }
        
        // Проверяем, что лимит исчерпан
        assertThat(rateLimitService.isAllowed(clientId)).isFalse();
        
        // Ждем немного (в реальном приложении это было бы минута)
        Thread.sleep(100);
        
        // Then - лимит все еще исчерпан (так как время не прошло)
        assertThat(rateLimitService.isAllowed(clientId)).isFalse();
    }
    
    @Test
    void testMultipleClientsIndependentLimits() {
        // Given
        String[] clientIds = {
            "192.168.1.800",
            "192.168.1.801", 
            "192.168.1.802",
            "192.168.1.803",
            "192.168.1.804"
        };
        
        // When - каждый клиент делает 10 запросов
        for (String clientId : clientIds) {
            for (int i = 0; i < 10; i++) {
                assertThat(rateLimitService.isAllowed(clientId)).isTrue();
            }
        }
        
        // Then - все клиенты должны быть заблокированы
        for (String clientId : clientIds) {
            assertThat(rateLimitService.isAllowed(clientId)).isFalse();
        }
    }
}
