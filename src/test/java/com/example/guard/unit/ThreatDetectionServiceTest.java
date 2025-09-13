package com.example.guard.unit;

import com.example.guard.service.ThreatDetectionService;
import com.example.guard.service.ThreatDetectionService.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit тесты для ThreatDetectionService
 */
@SpringBootTest
@ActiveProfiles("test")
class ThreatDetectionServiceTest {

    private ThreatDetectionService threatDetectionService;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        threatDetectionService = new ThreatDetectionService();
        request = new MockHttpServletRequest();
    }

    @Test
    void testAnalyzeRequest_NoThreats() {
        // Given
        request.setRequestURI("/public/info");
        request.setMethod("GET");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.LOW);
    }

    @Test
    void testAnalyzeRequest_SqlInjectionInParameter() {
        // Given
        request.setRequestURI("/public/search");
        request.setMethod("GET");
        request.addParameter("query", "'; DROP TABLE users; --");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_XssInParameter() {
        // Given
        request.setRequestURI("/public/comment");
        request.setMethod("POST");
        request.addParameter("comment", "<script>alert('XSS')</script>");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_PathTraversalInUri() {
        // Given
        request.setRequestURI("/public/../../../etc/passwd");
        request.setMethod("GET");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_CommandInjectionInParameter() {
        // Given
        request.setRequestURI("/public/execute");
        request.setMethod("POST");
        request.addParameter("command", "; ls -la");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_SuspiciousUserAgent() {
        // Given
        request.setRequestURI("/public/info");
        request.setMethod("GET");
        request.addHeader("User-Agent", "sqlmap/1.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_MissingUserAgent() {
        // Given
        request.setRequestURI("/public/info");
        request.setMethod("GET");
        // User-Agent не установлен

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    void testAnalyzeRequest_SuspiciousFileExtension() {
        // Given
        request.setRequestURI("/public/file.php");
        request.setMethod("GET");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    void testAnalyzeRequest_UnusualHttpMethod() {
        // Given
        request.setRequestURI("/public/info");
        request.setMethod("TRACE");
        request.addHeader("User-Agent", "Mozilla/5.0");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    void testAnalyzeRequest_MultipleXForwardedFor() {
        // Given
        request.setRequestURI("/public/info");
        request.setMethod("GET");
        request.addHeader("User-Agent", "Mozilla/5.0");
        request.addHeader("X-Forwarded-For", "192.168.1.1, 10.0.0.1, 172.16.0.1");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    void testGetThreatDetails() {
        // Given
        request.setRequestURI("/public/test");
        request.setMethod("GET");
        request.addHeader("User-Agent", "Mozilla/5.0");
        request.setRemoteAddr("192.168.1.100");

        // When
        var details = threatDetectionService.getThreatDetails(request);

        // Then
        assertThat(details).containsKeys("uri", "method", "userAgent", "clientIp", "timestamp", "threatLevel");
        assertThat(details.get("uri")).isEqualTo("/public/test");
        assertThat(details.get("method")).isEqualTo("GET");
        assertThat(details.get("clientIp")).isEqualTo("192.168.1.100");
    }

    @Test
    void testAnalyzeRequest_ComplexAttack() {
        // Given
        request.setRequestURI("/admin/../../../etc/passwd");
        request.setMethod("POST");
        request.addParameter("username", "admin");
        request.addParameter("password", "'; DROP TABLE users; --");
        request.addParameter("comment", "<script>alert('XSS')</script>");
        request.addHeader("User-Agent", "sqlmap/1.0");
        request.addHeader("X-Forwarded-For", "192.168.1.1, 10.0.0.1");

        // When
        ThreatLevel result = threatDetectionService.analyzeRequest(request);

        // Then
        assertThat(result).isEqualTo(ThreatLevel.HIGH);
    }
}
