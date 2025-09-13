package com.example.guard.config;

import com.example.guard.service.RateLimitService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class RateLimitConfig {
    
    @Bean
    public RateLimitService rateLimitService() {
        return new RateLimitService();
    }
    
    /**
     * Очистка старых записей rate limiting каждые 5 минут
     */
    @Scheduled(fixedRate = 300000) // 5 минут
    public void cleanupRateLimitData() {
        rateLimitService().cleanup();
    }
}

