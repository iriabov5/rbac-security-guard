package com.example.guard.integration;

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
import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AdminEndpointSecurityTest {
    
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
    void testAdminCanGetAllUsers() {
        // Тест: админ может получить список всех пользователей
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
    void testAdminCanGetSystemInfo() {
        // Тест: админ может получить информацию о системе
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("admin", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/admin/system", 
            HttpMethod.GET, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("systemStatus");
    }
    
    @Test
    void testUserCannotAccessAdminEndpoints() {
        // Тест: обычный пользователь не может получить доступ к админским эндпоинтам
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("user", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        // Тестируем несколько админских эндпоинтов
        String[] adminEndpoints = {
            "/admin/users",
            "/admin/system"
        };
        
        for (String endpoint : adminEndpoints) {
            ResponseEntity<String> response = restTemplate.exchange(
                getBaseUrl() + endpoint, 
                HttpMethod.GET, 
                entity, 
                String.class
            );
            
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }
    
    @Test
    void testAdminCanDeleteUser() {
        // Тест: админ может удалить пользователя
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("admin", "password");
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        // Находим ID пользователя "user" (не admin)
        List<User> users = userRepository.findAll();
        User userToDelete = users.stream()
            .filter(u -> "user".equals(u.getUsername()))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        ResponseEntity<String> response = restTemplate.exchange(
            getBaseUrl() + "/admin/users/" + userToDelete.getId(), 
            HttpMethod.DELETE, 
            entity, 
            String.class
        );
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("User deleted successfully");
    }
}
