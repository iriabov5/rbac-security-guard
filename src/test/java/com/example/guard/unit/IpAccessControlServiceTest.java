package com.example.guard.unit;

import com.example.guard.service.IpAccessControlService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit тесты для IpAccessControlService
 */
@SpringBootTest
@ActiveProfiles("test")
class IpAccessControlServiceTest {

    private IpAccessControlService ipAccessControlService;

    @BeforeEach
    void setUp() {
        ipAccessControlService = new IpAccessControlService();
    }

    @Test
    void testIsAccessAllowed_DefaultMode_AllowedIp() {
        // Given
        String ip = "192.168.1.100";

        // When
        boolean result = ipAccessControlService.isAccessAllowed(ip);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void testIsAccessAllowed_BlacklistedIp() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.addToBlacklist(ip);

        // When
        boolean result = ipAccessControlService.isAccessAllowed(ip);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void testIsAccessAllowed_WhitelistMode_WhitelistedIp() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.setWhitelistMode(true);
        ipAccessControlService.addToWhitelist(ip);

        // When
        boolean result = ipAccessControlService.isAccessAllowed(ip);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void testIsAccessAllowed_WhitelistMode_NonWhitelistedIp() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.setWhitelistMode(true);
        // IP не добавлен в белый список

        // When
        boolean result = ipAccessControlService.isAccessAllowed(ip);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void testAddToBlacklist() {
        // Given
        String ip = "192.168.1.100";

        // When
        ipAccessControlService.addToBlacklist(ip);

        // Then
        Set<String> blacklist = ipAccessControlService.getBlacklistedIps();
        assertThat(blacklist).contains(ip);
    }

    @Test
    void testRemoveFromBlacklist() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.addToBlacklist(ip);

        // When
        ipAccessControlService.removeFromBlacklist(ip);

        // Then
        Set<String> blacklist = ipAccessControlService.getBlacklistedIps();
        assertThat(blacklist).doesNotContain(ip);
    }

    @Test
    void testAddToWhitelist() {
        // Given
        String ip = "192.168.1.100";

        // When
        ipAccessControlService.addToWhitelist(ip);

        // Then
        Set<String> whitelist = ipAccessControlService.getWhitelistedIps();
        assertThat(whitelist).contains(ip);
    }

    @Test
    void testRemoveFromWhitelist() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.addToWhitelist(ip);

        // When
        ipAccessControlService.removeFromWhitelist(ip);

        // Then
        Set<String> whitelist = ipAccessControlService.getWhitelistedIps();
        assertThat(whitelist).doesNotContain(ip);
    }

    @Test
    void testRecordFailedAttempt() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.setMaxFailedAttempts(3);

        // When
        ipAccessControlService.recordFailedAttempt(ip);
        ipAccessControlService.recordFailedAttempt(ip);
        ipAccessControlService.recordFailedAttempt(ip);

        // Then
        Map<String, Object> stats = ipAccessControlService.getIpStatistics(ip);
        assertThat(stats.get("failedAttempts")).isEqualTo(3L);
        assertThat(stats.get("isTemporarilyBlocked")).isEqualTo(true);
    }

    @Test
    void testRecordSuccessfulAttempt() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.recordFailedAttempt(ip);
        ipAccessControlService.recordFailedAttempt(ip);

        // When
        ipAccessControlService.recordSuccessfulAttempt(ip);

        // Then
        Map<String, Object> stats = ipAccessControlService.getIpStatistics(ip);
        assertThat(stats.get("failedAttempts")).isEqualTo(0L);
        assertThat(stats.get("accessAttempts")).isEqualTo(1L);
    }

    @Test
    void testTemporarilyBlockIp() {
        // Given
        String ip = "192.168.1.100";

        // When
        ipAccessControlService.temporarilyBlockIp(ip);

        // Then
        boolean isBlocked = ipAccessControlService.isAccessAllowed(ip);
        assertThat(isBlocked).isFalse();
    }

    @Test
    void testGetIpStatistics() {
        // Given
        String ip = "192.168.1.100";
        ipAccessControlService.recordSuccessfulAttempt(ip);
        ipAccessControlService.recordFailedAttempt(ip);

        // When
        Map<String, Object> stats = ipAccessControlService.getIpStatistics(ip);

        // Then
        assertThat(stats).containsKeys("ip", "accessAttempts", "failedAttempts", 
            "isBlacklisted", "isWhitelisted", "isTemporarilyBlocked");
        assertThat(stats.get("ip")).isEqualTo(ip);
        assertThat(stats.get("accessAttempts")).isEqualTo(1L);
        assertThat(stats.get("failedAttempts")).isEqualTo(1L);
        assertThat(stats.get("isBlacklisted")).isEqualTo(false);
        assertThat(stats.get("isWhitelisted")).isEqualTo(false);
    }

    @Test
    void testGetTopAccessIps() {
        // Given
        ipAccessControlService.recordSuccessfulAttempt("192.168.1.1");
        ipAccessControlService.recordSuccessfulAttempt("192.168.1.1");
        ipAccessControlService.recordSuccessfulAttempt("192.168.1.2");

        // When
        Map<String, Long> topIps = ipAccessControlService.getTopAccessIps(2);

        // Then
        assertThat(topIps).hasSize(2);
        assertThat(topIps.get("192.168.1.1")).isEqualTo(2L);
        assertThat(topIps.get("192.168.1.2")).isEqualTo(1L);
    }

    @Test
    void testGetTopFailedIps() {
        // Given
        ipAccessControlService.recordFailedAttempt("192.168.1.1");
        ipAccessControlService.recordFailedAttempt("192.168.1.1");
        ipAccessControlService.recordFailedAttempt("192.168.1.2");

        // When
        Map<String, Long> topIps = ipAccessControlService.getTopFailedIps(2);

        // Then
        assertThat(topIps).hasSize(2);
        assertThat(topIps.get("192.168.1.1")).isEqualTo(2L);
        assertThat(topIps.get("192.168.1.2")).isEqualTo(1L);
    }

    @Test
    void testSetWhitelistMode() {
        // Given
        String ip = "192.168.1.100";

        // When
        ipAccessControlService.setWhitelistMode(true);

        // Then
        Map<String, Object> settings = ipAccessControlService.getSettings();
        assertThat(settings.get("whitelistMode")).isEqualTo(true);
        assertThat(ipAccessControlService.isAccessAllowed(ip)).isFalse();
    }

    @Test
    void testSetMaxFailedAttempts() {
        // When
        ipAccessControlService.setMaxFailedAttempts(10);

        // Then
        Map<String, Object> settings = ipAccessControlService.getSettings();
        assertThat(settings.get("maxFailedAttempts")).isEqualTo(10);
    }

    @Test
    void testSetBlockDurationMinutes() {
        // When
        ipAccessControlService.setBlockDurationMinutes(120);

        // Then
        Map<String, Object> settings = ipAccessControlService.getSettings();
        assertThat(settings.get("blockDurationMinutes")).isEqualTo(120L);
    }

    @Test
    void testGetSettings() {
        // When
        Map<String, Object> settings = ipAccessControlService.getSettings();

        // Then
        assertThat(settings).containsKeys("whitelistMode", "maxFailedAttempts", 
            "blockDurationMinutes", "blacklistedCount", "whitelistedCount", "temporarilyBlockedCount");
        assertThat(settings.get("whitelistMode")).isEqualTo(false);
        assertThat(settings.get("maxFailedAttempts")).isEqualTo(5);
        assertThat(settings.get("blockDurationMinutes")).isEqualTo(60L);
    }
}
