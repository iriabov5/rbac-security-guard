package com.example.guard.service;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Сервис для обнаружения угроз в HTTP запросах
 * Реализует правила обнаружения различных типов атак
 */
@Service
public class ThreatDetectionService {

    private static final Logger logger = LoggerFactory.getLogger(ThreatDetectionService.class);

    public enum ThreatLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    // Паттерны для обнаружения SQL инъекций
    private static final List<Pattern> SQL_INJECTION_PATTERNS = Arrays.asList(
        Pattern.compile("(?i).*union.*select.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*drop\\s+table.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*delete\\s+from.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*insert\\s+into.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*update\\s+.*set.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*or\\s+1\\s*=\\s*1.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*'\\s*or\\s*'.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*;\\s*drop.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*--.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*/\\*.*\\*/.*", Pattern.CASE_INSENSITIVE)
    );

    // Паттерны для обнаружения XSS атак
    private static final List<Pattern> XSS_PATTERNS = Arrays.asList(
        Pattern.compile("(?i).*<script.*>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*javascript:.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*onload\\s*=.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*onerror\\s*=.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*onclick\\s*=.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*<iframe.*>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*<object.*>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*<embed.*>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*<link.*>.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*<meta.*>.*", Pattern.CASE_INSENSITIVE)
    );

    // Паттерны для обнаружения Path Traversal атак
    private static final List<Pattern> PATH_TRAVERSAL_PATTERNS = Arrays.asList(
        Pattern.compile(".*\\.\\..*"),
        Pattern.compile(".*%2e%2e.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*%252e%252e.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\.\\./.*"),
        Pattern.compile(".*\\.\\.\\\\\\.*"),
        Pattern.compile(".*%2f.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*%5c.*", Pattern.CASE_INSENSITIVE)
    );

    // Паттерны для обнаружения Command Injection
    private static final List<Pattern> COMMAND_INJECTION_PATTERNS = Arrays.asList(
        Pattern.compile(".*;\\s*ls.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*;\\s*cat.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*;\\s*rm.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*;\\s*ps.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*;\\s*whoami.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\|\\s*ls.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\|\\s*cat.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*`.*`.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\$\\{.*\\}.*", Pattern.CASE_INSENSITIVE)
    );

    // Подозрительные User-Agent строки
    private static final List<Pattern> SUSPICIOUS_USER_AGENTS = Arrays.asList(
        Pattern.compile("(?i).*sqlmap.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*nikto.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*nmap.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*burp.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*zap.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*scanner.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*bot.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i).*crawler.*", Pattern.CASE_INSENSITIVE)
    );

    // Подозрительные заголовки
    private static final List<String> SUSPICIOUS_HEADERS = Arrays.asList(
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Client-IP", "X-Host", "X-Forwarded-Host"
    );

    /**
     * Анализ HTTP запроса на предмет угроз
     */
    public ThreatLevel analyzeRequest(HttpServletRequest request) {
        ThreatLevel maxThreatLevel = ThreatLevel.LOW;
        List<String> detectedThreats = new ArrayList<>();

        // 1. Анализ URI
        String uri = request.getRequestURI();
        ThreatLevel uriThreat = analyzeUri(uri);
        if (uriThreat.ordinal() > maxThreatLevel.ordinal()) {
            maxThreatLevel = uriThreat;
        }

        // 2. Анализ параметров запроса
        ThreatLevel paramsThreat = analyzeParameters(request);
        if (paramsThreat.ordinal() > maxThreatLevel.ordinal()) {
            maxThreatLevel = paramsThreat;
        }

        // 3. Анализ заголовков
        ThreatLevel headersThreat = analyzeHeaders(request);
        if (headersThreat.ordinal() > maxThreatLevel.ordinal()) {
            maxThreatLevel = headersThreat;
        }

        // 4. Анализ User-Agent
        ThreatLevel userAgentThreat = analyzeUserAgent(request);
        if (userAgentThreat.ordinal() > maxThreatLevel.ordinal()) {
            maxThreatLevel = userAgentThreat;
        }

        // 5. Анализ метода запроса
        ThreatLevel methodThreat = analyzeMethod(request);
        if (methodThreat.ordinal() > maxThreatLevel.ordinal()) {
            maxThreatLevel = methodThreat;
        }

        if (maxThreatLevel != ThreatLevel.LOW) {
            logger.warn("🚨 Обнаружена угроза уровня {}: {}", maxThreatLevel, detectedThreats);
        }

        return maxThreatLevel;
    }

    /**
     * Анализ URI на предмет подозрительных паттернов
     */
    private ThreatLevel analyzeUri(String uri) {
        // Проверка на Path Traversal
        for (Pattern pattern : PATH_TRAVERSAL_PATTERNS) {
            if (pattern.matcher(uri).matches()) {
                logger.warn("🚨 Path Traversal обнаружен в URI: {}", uri);
                return ThreatLevel.HIGH;
            }
        }

        // Проверка на подозрительные расширения файлов
        if (uri.matches(".*\\.(php|asp|jsp|cgi|pl|py|sh|bat|exe|dll)$")) {
            logger.warn("🚨 Подозрительное расширение файла в URI: {}", uri);
            return ThreatLevel.HIGH; // Повышаем до HIGH для блокировки
        }

        // Проверка на длинные URI (возможная атака)
        if (uri.length() > 2048) {
            logger.warn("🚨 Слишком длинный URI: {} символов", uri.length());
            return ThreatLevel.HIGH; // Повышаем до HIGH для блокировки
        }

        return ThreatLevel.LOW;
    }

    /**
     * Анализ параметров запроса
     */
    private ThreatLevel analyzeParameters(HttpServletRequest request) {
        ThreatLevel maxThreat = ThreatLevel.LOW;

        // Анализ query параметров
        Map<String, String[]> parameterMap = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            String paramName = entry.getKey();
            String[] paramValues = entry.getValue();

            for (String paramValue : paramValues) {
                // Проверка на SQL инъекции
                ThreatLevel sqlThreat = checkPatterns(paramValue, SQL_INJECTION_PATTERNS, "SQL_INJECTION");
                if (sqlThreat.ordinal() > maxThreat.ordinal()) {
                    maxThreat = sqlThreat;
                }

                // Проверка на XSS
                ThreatLevel xssThreat = checkPatterns(paramValue, XSS_PATTERNS, "XSS");
                if (xssThreat.ordinal() > maxThreat.ordinal()) {
                    maxThreat = xssThreat;
                }

                // Проверка на Command Injection
                ThreatLevel cmdThreat = checkPatterns(paramValue, COMMAND_INJECTION_PATTERNS, "COMMAND_INJECTION");
                if (cmdThreat.ordinal() > maxThreat.ordinal()) {
                    maxThreat = cmdThreat;
                }
            }
        }

        return maxThreat;
    }

    /**
     * Анализ HTTP заголовков
     */
    private ThreatLevel analyzeHeaders(HttpServletRequest request) {
        // Проверка на подозрительные заголовки
        for (String headerName : SUSPICIOUS_HEADERS) {
            String headerValue = request.getHeader(headerName);
            if (headerValue != null && !headerValue.isEmpty()) {
                logger.debug("🔍 Обнаружен заголовок {}: {}", headerName, headerValue);
                
                // Проверка на множественные IP адреса (возможная атака)
                if (headerValue.contains(",")) {
                    logger.warn("⚠️ Множественные IP адреса в заголовке {}: {}", headerName, headerValue);
                    return ThreatLevel.MEDIUM;
                }
            }
        }

        // Проверка на отсутствие User-Agent
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.trim().isEmpty()) {
            logger.warn("⚠️ Отсутствует User-Agent заголовок");
            return ThreatLevel.MEDIUM;
        }

        return ThreatLevel.LOW;
    }

    /**
     * Анализ User-Agent
     */
    private ThreatLevel analyzeUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            return ThreatLevel.LOW;
        }

        // Проверка на подозрительные User-Agent
        for (Pattern pattern : SUSPICIOUS_USER_AGENTS) {
            if (pattern.matcher(userAgent).matches()) {
                logger.warn("🚨 Подозрительный User-Agent: {}", userAgent);
                return ThreatLevel.HIGH;
            }
        }

        return ThreatLevel.LOW;
    }

    /**
     * Анализ HTTP метода
     */
    private ThreatLevel analyzeMethod(HttpServletRequest request) {
        String method = request.getMethod();
        
        // Проверка на необычные методы
        if (!Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS").contains(method)) {
            logger.warn("⚠️ Необычный HTTP метод: {}", method);
            return ThreatLevel.MEDIUM;
        }

        return ThreatLevel.LOW;
    }

    /**
     * Проверка строки на соответствие паттернам
     */
    private ThreatLevel checkPatterns(String input, List<Pattern> patterns, String threatType) {
        for (Pattern pattern : patterns) {
            if (pattern.matcher(input).matches()) {
                logger.warn("🚨 {} обнаружен: {}", threatType, input);
                return ThreatLevel.HIGH;
            }
        }
        return ThreatLevel.LOW;
    }

    /**
     * Получение детальной информации об обнаруженных угрозах
     */
    public Map<String, Object> getThreatDetails(HttpServletRequest request) {
        Map<String, Object> details = new HashMap<>();
        details.put("uri", request.getRequestURI());
        details.put("method", request.getMethod());
        details.put("userAgent", request.getHeader("User-Agent"));
        details.put("clientIp", getClientIp(request));
        details.put("timestamp", new Date());
        details.put("threatLevel", analyzeRequest(request));
        
        return details;
    }

    /**
     * Получение IP адреса клиента
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
