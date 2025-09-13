package com.example.guard.service;

import com.example.guard.dto.UserDto;
import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    /**
     * Создает нового пользователя
     */
    public User createUser(String username, String password, Role role) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }
        
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(true);
        
        return userRepository.save(user);
    }
    
    /**
     * Находит пользователя по имени
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    /**
     * Получает всех пользователей
     */
    public List<UserDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }
    
    /**
     * Получает пользователей по роли
     */
    public List<UserDto> getUsersByRole(Role role) {
        return userRepository.findAll().stream()
                .filter(user -> user.getRole() == role)
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }
    
    /**
     * Удаляет пользователя по ID
     */
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalArgumentException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
    }
    
    /**
     * Блокирует/разблокирует пользователя
     */
    public void toggleUserStatus(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
        
        user.setEnabled(!user.isEnabled());
        userRepository.save(user);
    }
    
    /**
     * Обновляет время последнего входа
     */
    public void updateLastLogin(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setLastLogin(LocalDateTime.now());
            user.resetLoginAttempts();
            userRepository.save(user);
        }
    }
    
    /**
     * Увеличивает счетчик неудачных попыток входа
     */
    public void incrementLoginAttempts(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.incrementLoginAttempts();
            
            // Блокируем аккаунт после 5 неудачных попыток на 15 минут
            if (user.getLoginAttempts() >= 5) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(15));
            }
            
            userRepository.save(user);
        }
    }
    
    /**
     * Получает статистику пользователей
     */
    public UserStats getUserStats() {
        long totalUsers = userRepository.count();
        long adminCount = userRepository.countByRole(Role.ADMIN);
        long userCount = userRepository.countByRole(Role.USER);
        
        return new UserStats(totalUsers, adminCount, userCount);
    }
    
    /**
     * Конвертирует User в UserDto
     */
    private UserDto convertToDto(User user) {
        return new UserDto(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                user.isEnabled(),
                user.getLastLogin(),
                user.getLoginAttempts(),
                user.getLockedUntil()
        );
    }
    
    /**
     * Класс для статистики пользователей
     */
    public static class UserStats {
        private final long totalUsers;
        private final long adminCount;
        private final long userCount;
        
        public UserStats(long totalUsers, long adminCount, long userCount) {
            this.totalUsers = totalUsers;
            this.adminCount = adminCount;
            this.userCount = userCount;
        }
        
        public long getTotalUsers() { return totalUsers; }
        public long getAdminCount() { return adminCount; }
        public long getUserCount() { return userCount; }
    }
}

