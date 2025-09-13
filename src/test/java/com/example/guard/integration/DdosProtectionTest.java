package com.example.guard.integration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.annotation.Commit;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class DdosProtectionTest {
    
    @LocalServerPort
    private int port;
    
    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    private String getBaseUrl() {
        return "http://localhost:" + port;
    }

    @BeforeEach
    @Commit
    void setUp() {
        // Очищаем базу данных перед каждым тестом
        userRepository.deleteAll();
        
        // Создаем тестовых пользователей
        createTestUsers();
    }

    private void createTestUsers() {
        // Создаем обычного пользователя
        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole(Role.USER);
        user.setEnabled(true);
        userRepository.save(user);

        // Создаем администратора
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRole(Role.ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);
    }
    
    @Test
    void testDdosProtection() throws InterruptedException {
        String clientId = "192.168.1.100";
        String endpoint = "/public/info";
        
        // Имитируем DDoS атаку - отправляем много запросов подряд
        List<CompletableFuture<ResponseEntity<String>>> futures = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(20);
        
        // Отправляем 15 запросов (больше лимита в 10)
        for (int i = 0; i < 15; i++) {
            CompletableFuture<ResponseEntity<String>> future = CompletableFuture.supplyAsync(() -> {
                HttpHeaders headers = new HttpHeaders();
                headers.set("X-Forwarded-For", clientId);
                HttpEntity<String> entity = new HttpEntity<>(headers);
                
                return restTemplate.exchange(
                    endpoint, 
                    HttpMethod.GET, 
                    entity, 
                    String.class
                );
            }, executor);
            futures.add(future);
        }
        
        // Ждем завершения всех запросов
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();
        
        // Проверяем результаты
        int successCount = 0;
        int blockedCount = 0;
        
        for (CompletableFuture<ResponseEntity<String>> future : futures) {
            try {
                ResponseEntity<String> response = future.get();
                if (response.getStatusCode().is2xxSuccessful()) {
                    successCount++;
                } else if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                    blockedCount++;
                }
            } catch (Exception e) {
                blockedCount++;
            }
        }
        
        // Проверяем, что система заблокировала часть запросов
        assertThat(successCount).isLessThanOrEqualTo(10); // Максимум 10 успешных
        assertThat(blockedCount).isGreaterThan(0); // Хотя бы один заблокирован
        
        System.out.println("DDoS Protection Test Results:");
        System.out.println("Successful requests: " + successCount);
        System.out.println("Blocked requests: " + blockedCount);
    }
    
    @Test
    void testRateLimitReset() throws InterruptedException {
        String clientId = "192.168.1.101";
        String endpoint = "/public/status";
        
        // Исчерпываем лимит
        for (int i = 0; i < 10; i++) {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Forwarded-For", clientId);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.GET, 
                entity, 
                String.class
            );
            assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        }
        
        // 11-й запрос должен быть заблокирован
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", clientId);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            endpoint, 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
    
    
    @Test
    void testDifferentClientsHaveSeparateLimits() {
        String clientId1 = "192.168.1.200";
        String clientId2 = "192.168.1.201";
        String endpoint = "/public/info";
        
        // Исчерпываем лимит для первого клиента
        for (int i = 0; i < 10; i++) {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Forwarded-For", clientId1);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.GET, 
                entity, 
                String.class
            );
            assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        }
        
        // Проверяем, что первый клиент заблокирован
        HttpHeaders headers1 = new HttpHeaders();
        headers1.set("X-Forwarded-For", clientId1);
        HttpEntity<String> entity1 = new HttpEntity<>(headers1);
        
        ResponseEntity<String> response1 = restTemplate.exchange(
            endpoint, 
            HttpMethod.GET, 
            entity1, 
            String.class
        );
        assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        
        // Проверяем, что второй клиент все еще может делать запросы
        HttpHeaders headers2 = new HttpHeaders();
        headers2.set("X-Forwarded-For", clientId2);
        HttpEntity<String> entity2 = new HttpEntity<>(headers2);
        
        ResponseEntity<String> response2 = restTemplate.exchange(
            endpoint, 
            HttpMethod.GET, 
            entity2, 
            String.class
        );
        assertThat(response2.getStatusCode().is2xxSuccessful()).isTrue();
    }
    
    @Test
    void testRateLimitWithAuthentication() {
        String clientId = "192.168.1.300";
        String endpoint = "/user/profile";
        
        // Исчерпываем лимит для аутентифицированного пользователя
        for (int i = 0; i < 10; i++) {
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Forwarded-For", clientId);
            headers.setBasicAuth("user", "password");
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.GET, 
                entity, 
                String.class
            );
            assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        }
        
        // 11-й запрос должен быть заблокирован
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Forwarded-For", clientId);
        headers.setBasicAuth("user", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            endpoint, 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
    
    @Test
    void testConcurrentRequestsFromSameClient() throws InterruptedException {
        String clientId = "192.168.1.400";
        String endpoint = "/public/info";
        
        // Отправляем 20 одновременных запросов от одного клиента
        List<CompletableFuture<ResponseEntity<String>>> futures = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(20);
        
        for (int i = 0; i < 20; i++) {
            CompletableFuture<ResponseEntity<String>> future = CompletableFuture.supplyAsync(() -> {
                HttpHeaders headers = new HttpHeaders();
                headers.set("X-Forwarded-For", clientId);
                HttpEntity<String> entity = new HttpEntity<>(headers);
                
                return restTemplate.exchange(
                    endpoint, 
                    HttpMethod.GET, 
                    entity, 
                    String.class
                );
            }, executor);
            futures.add(future);
        }
        
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();
        
        // Подсчитываем результаты
        int successCount = 0;
        int blockedCount = 0;
        
        for (CompletableFuture<ResponseEntity<String>> future : futures) {
            try {
                ResponseEntity<String> response = future.get();
                if (response.getStatusCode().is2xxSuccessful()) {
                    successCount++;
                } else if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                    blockedCount++;
                }
            } catch (Exception e) {
                blockedCount++;
            }
        }
        
        // Проверяем, что не более 10 запросов прошли успешно
        assertThat(successCount).isLessThanOrEqualTo(10);
        assertThat(blockedCount).isGreaterThanOrEqualTo(10);
        
        System.out.println("Concurrent Requests Test Results:");
        System.out.println("Successful requests: " + successCount);
        System.out.println("Blocked requests: " + blockedCount);
    }
}
