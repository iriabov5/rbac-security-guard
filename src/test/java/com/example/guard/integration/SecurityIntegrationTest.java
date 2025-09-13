package com.example.guard.integration;

import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.annotation.Commit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class SecurityIntegrationTest {
    
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

        // Создаем отключенного пользователя
        User disabledUser = new User();
        disabledUser.setUsername("disableduser");
        disabledUser.setPassword(passwordEncoder.encode("password"));
        disabledUser.setRole(Role.USER);
        disabledUser.setEnabled(false);
        userRepository.save(disabledUser);
    }
    
    @Test
    void testPublicEndpointAccessible() {
        // Тест: публичный эндпоинт доступен без аутентификации
        ResponseEntity<String> response = restTemplate.getForEntity(
            getBaseUrl() + "/public/info", String.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Welcome to RBAC Security Guard");
    }
    
    @Test
    void testPublicStatusEndpointAccessible() {
        // Тест: публичный эндпоинт статуса доступен без аутентификации
        ResponseEntity<String> response = restTemplate.getForEntity(
            getBaseUrl() + "/public/status", String.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("System is running");
    }
    
    @Test
    void testUserEndpointRequiresAuth() {
        // Тест: эндпоинт пользователя требует аутентификации
        ResponseEntity<String> response = restTemplate.getForEntity(
            getBaseUrl() + "/user/profile", String.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testAdminEndpointRequiresAuth() {
        // Тест: эндпоинт админа требует аутентификации
        ResponseEntity<String> response = restTemplate.getForEntity(
            getBaseUrl() + "/admin/users", String.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testUserCanAccessUserEndpoints() {
        // Тест: пользователь с ролью USER может получить доступ к пользовательским эндпоинтам
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("user", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/user/profile", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("User profile");
    }
    
    @Test
    void testAdminCanAccessAdminEndpoints() {
        // Тест: пользователь с ролью ADMIN может получить доступ к админским эндпоинтам
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("admin", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/admin/users", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("admin");
    }
    
    @Test
    void testUserCannotAccessAdminEndpoints() {
        // Тест: пользователь с ролью USER не может получить доступ к админским эндпоинтам
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("user", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/admin/users", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
    
    @Test
    void testAdminCanAccessUserEndpoints() {
        // Тест: пользователь с ролью ADMIN может получить доступ к пользовательским эндпоинтам
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("admin", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/user/profile", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("User profile");
    }
    
    @Test
    void testInvalidCredentials() {
        // Тест: неверные учетные данные возвращают 401
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("user", "wrongpassword");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/user/profile", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testNonExistentUser() {
        // Тест: несуществующий пользователь возвращает 401
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("nonexistent", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/user/profile", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testDisabledUser() {
        // Тест: отключенный пользователь не может войти
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("disableduser", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/user/profile", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
