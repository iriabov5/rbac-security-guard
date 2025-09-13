# 🛡️ RBAC Security Guard

Полнофункциональный Spring Boot Security проект с RBAC (Role-Based Access Control) и защитой от DDoS атак.

## 🎯 Описание проекта

RBAC Security Guard - это демонстрационный проект, показывающий реализацию системы безопасности на Spring Boot с использованием:

- **Аутентификации** - вход по логину/паролю
- **Авторизации** - контроль доступа на основе ролей (RBAC)
- **Защиты от DDoS** - rate limiting для предотвращения атак
- **REST API** - простые эндпоинты для демонстрации функциональности

## 🚀 Технологический стек

- **Java 17**
- **Spring Boot 3.2.0**
- **Spring Security 6.x**
- **Spring Data JPA**
- **H2 Database** (в памяти)
- **Maven** (сборка)
- **JUnit 5** (тестирование)
- **TestContainers** (интеграционные тесты)

## 📋 Функциональные возможности

### 🔐 Аутентификация и авторизация
- Базовая HTTP аутентификация
- Две роли: `ADMIN` и `USER`
- Защита эндпоинтов по ролям
- Блокировка аккаунтов после неудачных попыток входа

### 🛡️ Защита от DDoS
- Rate limiting: 10 запросов в минуту на клиента
- Автоматическая очистка старых записей
- Отдельные лимиты для каждого IP-адреса
- HTTP 429 (Too Many Requests) при превышении лимита

### 🌐 REST API
- **Публичные эндпоинты** - доступны всем
- **Пользовательские эндпоинты** - требуют роль USER или ADMIN
- **Админские эндпоинты** - требуют роль ADMIN

## 🏗️ Структура проекта

```
rbac-security-guard/
├── src/main/java/com/example/guard/
│   ├── SecurityGuardApplication.java          # Главный класс приложения
│   ├── config/                                # Конфигурация
│   │   ├── SecurityConfig.java               # Настройки безопасности
│   │   ├── WebConfig.java                    # Web конфигурация
│   │   └── RateLimitConfig.java              # Rate limiting конфигурация
│   ├── controller/                           # REST контроллеры
│   │   ├── PublicController.java             # Публичные эндпоинты
│   │   ├── UserController.java               # Пользовательские эндпоинты
│   │   └── AdminController.java              # Админские эндпоинты
│   ├── entity/                               # JPA сущности
│   │   ├── User.java                         # Пользователь
│   │   └── Role.java                         # Роль (enum)
│   ├── repository/                           # Репозитории
│   │   ├── UserRepository.java               # Репозиторий пользователей
│   │   └── RoleRepository.java               # Репозиторий ролей
│   ├── service/                              # Бизнес-логика
│   │   ├── UserService.java                  # Сервис пользователей
│   │   ├── AuthService.java                  # Сервис аутентификации
│   │   └── RateLimitService.java             # Сервис rate limiting
│   ├── dto/                                  # Data Transfer Objects
│   │   ├── LoginRequest.java                 # Запрос входа
│   │   ├── LoginResponse.java                # Ответ входа
│   │   └── UserDto.java                      # DTO пользователя
│   └── exception/                            # Обработка исключений
│       ├── RateLimitExceededException.java   # Исключение rate limit
│       └── GlobalExceptionHandler.java       # Глобальный обработчик
├── src/test/java/com/example/guard/          # Тесты
│   ├── integration/                          # Интеграционные тесты
│   │   ├── SecurityIntegrationTest.java      # Тесты безопасности
│   │   ├── AdminEndpointSecurityTest.java    # Тесты админских эндпоинтов
│   │   └── DdosProtectionTest.java           # Тесты DDoS защиты
│   └── unit/                                 # Unit тесты
│       ├── UserServiceTest.java              # Тесты сервиса пользователей
│       ├── AuthServiceTest.java              # Тесты сервиса аутентификации
│       └── RateLimitServiceTest.java         # Тесты rate limiting
├── src/main/resources/
│   ├── application.yml                       # Конфигурация приложения
│   └── data.sql                              # Тестовые данные
├── README.md                                 # Этот файл
├── TUTORIAL.md                               # Пошаговый туториал
└── pom.xml                                   # Maven конфигурация
```

## 🚀 Быстрый старт

### Предварительные требования
- Java 17 или выше
- Maven 3.6 или выше

### Установка и запуск

1. **Клонируйте репозиторий:**
```bash
git clone <repository-url>
cd rbac-security-guard
```

2. **Соберите проект:**
```bash
mvn clean compile
```

3. **Запустите приложение:**
```bash
mvn spring-boot:run
```

4. **Приложение будет доступно по адресу:**
```
http://localhost:8080
```

5. **H2 консоль доступна по адресу:**
```
http://localhost:8080/h2-console
```

### Тестовые пользователи

| Username | Password | Role  | Описание |
|----------|----------|-------|----------|
| admin    | password | ADMIN | Администратор |
| user     | password | USER  | Обычный пользователь |
| testuser | password | USER  | Тестовый пользователь |
| testadmin| password | ADMIN | Тестовый администратор |

## 🌐 API Эндпоинты

### Публичные эндпоинты (доступны всем)

| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/public/info` | Публичная информация |
| GET | `/public/status` | Статус системы |
| GET | `/public/rate-limit-info` | Информация о rate limiting |
| GET | `/public/security-info` | Информация о безопасности |

### Пользовательские эндпоинты (требуют роль USER или ADMIN)

| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/user/profile` | Профиль пользователя |
| GET | `/user/dashboard` | Дашборд пользователя |
| GET | `/user/settings` | Настройки пользователя |
| PUT | `/user/settings` | Обновление настроек |
| GET | `/user/notifications` | Уведомления пользователя |

### Админские эндпоинты (требуют роль ADMIN)

| Метод | URL | Описание |
|-------|-----|----------|
| GET | `/admin/users` | Список всех пользователей |
| GET | `/admin/users/role/{role}` | Пользователи по роли |
| DELETE | `/admin/users/{id}` | Удаление пользователя |
| PUT | `/admin/users/{id}/toggle-status` | Блокировка/разблокировка |
| GET | `/admin/system` | Информация о системе |
| GET | `/admin/security-stats` | Статистика безопасности |

## 🧪 Тестирование

### Запуск всех тестов
```bash
mvn test
```

### Запуск только unit тестов
```bash
mvn test -Dtest="*Test"
```

### Запуск только интеграционных тестов
```bash
mvn test -Dtest="*IntegrationTest"
```

### Запуск тестов DDoS защиты
```bash
mvn test -Dtest="DdosProtectionTest"
```

## 🔧 Конфигурация

### Основные настройки (application.yml)

```yaml
# Rate limiting
rate-limit:
  max-requests: 10        # Максимум запросов
  window-duration: PT1M   # Временное окно (1 минута)

# База данных
spring:
  datasource:
    url: jdbc:h2:mem:testdb
  h2:
    console:
      enabled: true

# Логирование
logging:
  level:
    org.springframework.security: DEBUG
    com.example.guard: DEBUG
```

## 🛡️ Безопасность

### Аутентификация
- HTTP Basic Authentication
- BCrypt хеширование паролей
- Блокировка аккаунтов после 5 неудачных попыток

### Авторизация
- Role-Based Access Control (RBAC)
- Две роли: ADMIN и USER
- ADMIN имеет доступ ко всем эндпоинтам
- USER имеет доступ только к пользовательским эндпоинтам

### Защита от DDoS
- Rate limiting: 10 запросов в минуту
- Отдельные лимиты для каждого IP-адреса
- Автоматическая очистка старых записей
- HTTP 429 при превышении лимита

## 📊 Мониторинг

### H2 Console
- URL: `http://localhost:8080/h2-console`
- JDBC URL: `jdbc:h2:mem:testdb`
- Username: `sa`
- Password: `password`

### Логи
- Уровень DEBUG для Spring Security
- Подробные логи SQL запросов
- Логи rate limiting

## 🚨 Примеры использования

### Тестирование публичных эндпоинтов
```bash
curl http://localhost:8080/public/info
curl http://localhost:8080/public/status
```

### Тестирование с аутентификацией
```bash
# Пользовательские эндпоинты
curl -u user:password http://localhost:8080/user/profile
curl -u user:password http://localhost:8080/user/dashboard

# Админские эндпоинты
curl -u admin:password http://localhost:8080/admin/users
curl -u admin:password http://localhost:8080/admin/system
```

### Тестирование DDoS защиты
```bash
# Отправляем 15 запросов подряд (больше лимита в 10)
for i in {1..15}; do curl http://localhost:8080/public/info; done
```

### Тестирование авторизации
```bash
# Пользователь не может получить доступ к админским эндпоинтам
curl -u user:password http://localhost:8080/admin/users
# Должен вернуть 403 Forbidden
```

## 🔍 Отладка

### Включение подробных логов
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.example.guard: DEBUG
    org.hibernate.SQL: DEBUG
```

### Проверка rate limiting
```bash
# Проверка информации о лимитах
curl http://localhost:8080/public/rate-limit-info
```

## 📝 Лицензия

Этот проект создан в образовательных целях и доступен под лицензией MIT.

## 🤝 Вклад в проект

1. Fork проекта
2. Создайте feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit изменения (`git commit -m 'Add some AmazingFeature'`)
4. Push в branch (`git push origin feature/AmazingFeature`)
5. Откройте Pull Request

## 📞 Поддержка

Если у вас есть вопросы или предложения, создайте issue в репозитории.

---

**RBAC Security Guard** - надежная защита вашего Spring Boot приложения! 🛡️

