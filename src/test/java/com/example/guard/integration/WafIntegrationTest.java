package com.example.guard.integration;

import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.annotation.Commit;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.http.HttpMethod;

/**
 * Интеграционные тесты для Web Application Firewall (WAF)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "logging.level.com.example.guard.security=DEBUG",
    "logging.level.SECURITY=DEBUG"
})
class WafIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    @Commit
    void setUp() {
        // Очистка базы данных
        userRepository.deleteAll();

        // Создание тестовых пользователей
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin123"));
        admin.setRole(Role.ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);

        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("user123"));
        user.setRole(Role.USER);
        user.setEnabled(true);
        userRepository.save(user);
    }

    @Test
    void testWaf_BlocksSqlInjection() throws Exception {
        // Given - SQL инъекция в параметре
        String sqlInjection = "'; DROP TABLE users; --";

        // When & Then
        mockMvc.perform(get("/public/info")
                .param("query", sqlInjection))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_BlocksXssAttack() throws Exception {
        // Given - XSS атака в параметре
        String xssPayload = "<script>alert('XSS')</script>";

        // When & Then
        mockMvc.perform(get("/public/info")
                .param("comment", xssPayload))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_BlocksPathTraversal() throws Exception {
        // Given - Path Traversal атака в URI
        String pathTraversal = "/public/../../../etc/passwd";

        // When & Then
        mockMvc.perform(get(pathTraversal)
                .header("User-Agent", "Mozilla/5.0"))
                .andExpect(status().isBadRequest()) // Spring Security возвращает 400 для некорректных путей
                .andExpect(content().string(""));
    }

    @Test
    void testWaf_BlocksCommandInjection() throws Exception {
        // Given - Command Injection в параметре
        String commandInjection = "; ls -la";

        // When & Then
        mockMvc.perform(post("/public/execute")
                .param("command", commandInjection))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_BlocksSuspiciousUserAgent() throws Exception {
        // Given - Подозрительный User-Agent
        String suspiciousUserAgent = "sqlmap/1.0";

        // When & Then
        mockMvc.perform(get("/public/info")
                .header("User-Agent", suspiciousUserAgent))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_AllowsNormalRequests() throws Exception {
        // Given - Нормальный запрос
        String normalUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        // When & Then
        mockMvc.perform(get("/public/info")
                .header("User-Agent", normalUserAgent))
                .andExpect(status().isOk());
    }

    @Test
    void testWaf_AddsSecurityHeaders() throws Exception {
        // When & Then
        mockMvc.perform(get("/public/info")
                .header("User-Agent", "Mozilla/5.0"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().exists("X-Frame-Options")) // Может быть DENY или SAMEORIGIN
                .andExpect(header().string("X-XSS-Protection", "1; mode=block"))
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().exists("Referrer-Policy"))
                .andExpect(header().exists("Permissions-Policy"))
                .andExpect(header().exists("Strict-Transport-Security"));
    }

    @Test
    void testWaf_BlocksMissingUserAgent() throws Exception {
        // When & Then - Запрос без User-Agent должен быть заблокирован
        mockMvc.perform(get("/public/info"))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_BlocksSuspiciousFileExtension() throws Exception {
        // Given - Подозрительное расширение файла
        String suspiciousPath = "/public/file.php";

        // When & Then
        mockMvc.perform(get(suspiciousPath)
                .header("User-Agent", "Mozilla/5.0"))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_BlocksUnusualHttpMethod() throws Exception {
        // When & Then - Необычный HTTP метод (TRACE)
        mockMvc.perform(MockMvcRequestBuilders.request(HttpMethod.TRACE, "/public/info")
                .header("User-Agent", "Mozilla/5.0"))
                .andExpect(status().isBadRequest()) // Spring Security блокирует TRACE на уровне сервера
                .andExpect(content().string(""));
    }

    @Test
    void testWaf_BlocksMultipleXForwardedFor() throws Exception {
        // Given - Множественные IP в X-Forwarded-For
        String multipleIps = "192.168.1.1, 10.0.0.1, 172.16.0.1";

        // When & Then
        mockMvc.perform(get("/public/info")
                .header("User-Agent", "Mozilla/5.0")
                .header("X-Forwarded-For", multipleIps))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_ComplexAttackScenario() throws Exception {
        // Given - Комплексная атака с несколькими векторами
        String sqlInjection = "'; DROP TABLE users; --";
        String xssPayload = "<script>alert('XSS')</script>";
        String suspiciousUserAgent = "nikto/2.1.6";

        // When & Then
        mockMvc.perform(post("/admin/users")
                .param("username", "admin")
                .param("password", sqlInjection)
                .param("comment", xssPayload)
                .header("User-Agent", suspiciousUserAgent)
                .header("Authorization", "Basic YWRtaW46YWRtaW4xMjM=")) // admin:admin123
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_AllowsAuthenticatedAdminAccess() throws Exception {
        // Given - Аутентифицированный админ с нормальным запросом
        String normalUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        // When & Then
        mockMvc.perform(get("/admin/users")
                .header("User-Agent", normalUserAgent)
                .header("Authorization", "Basic YWRtaW46YWRtaW4xMjM=")) // admin:admin123
                .andExpect(status().isOk());
    }

    @Test
    void testWaf_BlocksLongUri() throws Exception {
        // Given - Слишком длинный URI
        StringBuilder longUri = new StringBuilder("/public/");
        for (int i = 0; i < 3000; i++) {
            longUri.append("a");
        }

        // When & Then
        mockMvc.perform(get(longUri.toString())
                .header("User-Agent", "Mozilla/5.0"))
                .andExpect(status().isForbidden())
                .andExpect(content().string("{\"error\":\"Access denied by security policy\"}"));
    }

    @Test
    void testWaf_SecurityDashboardAccess() throws Exception {
        // Given - Аутентифицированный админ
        String normalUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        // When & Then - Доступ к Security Dashboard
        mockMvc.perform(get("/admin/security/stats")
                .header("User-Agent", normalUserAgent)
                .header("Authorization", "Basic YWRtaW46YWRtaW4xMjM=")) // admin:admin123
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.attackStats").exists())
                .andExpect(jsonPath("$.ipControlSettings").exists())
                .andExpect(jsonPath("$.rateLimitStats").exists());
    }

    @Test
    void testWaf_BlocksUnauthorizedSecurityDashboardAccess() throws Exception {
        // Given - Неаутентифицированный запрос к Security Dashboard
        String normalUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        // When & Then
        mockMvc.perform(get("/admin/security/stats")
                .header("User-Agent", normalUserAgent))
                .andExpect(status().isUnauthorized());
    }
}
