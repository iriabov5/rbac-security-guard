package com.example.guard.config;

import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@Profile("!test")
public class DataInitializer implements CommandLineRunner {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) throws Exception {
        // Создаем тестовых пользователей только если их еще нет
        if (userRepository.count() == 0) {
            createTestUsers();
        }
    }
    
    private void createTestUsers() {
        // Пароль для всех пользователей: "password"
        String encodedPassword = passwordEncoder.encode("password");
        
        // Создаем тестовых пользователей
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(encodedPassword);
        admin.setRole(Role.ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);
        
        User user = new User();
        user.setUsername("user");
        user.setPassword(encodedPassword);
        user.setRole(Role.USER);
        user.setEnabled(true);
        userRepository.save(user);
        
        User testUser = new User();
        testUser.setUsername("testuser");
        testUser.setPassword(encodedPassword);
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);
        userRepository.save(testUser);
        
        User testAdmin = new User();
        testAdmin.setUsername("testadmin");
        testAdmin.setPassword(encodedPassword);
        testAdmin.setRole(Role.ADMIN);
        testAdmin.setEnabled(true);
        userRepository.save(testAdmin);
        
        User lockedUser = new User();
        lockedUser.setUsername("lockeduser");
        lockedUser.setPassword(encodedPassword);
        lockedUser.setRole(Role.USER);
        lockedUser.setEnabled(true);
        lockedUser.setLoginAttempts(5);
        lockedUser.setLockedUntil(LocalDateTime.now().plusMinutes(15));
        userRepository.save(lockedUser);
        
        User disabledUser = new User();
        disabledUser.setUsername("disableduser");
        disabledUser.setPassword(encodedPassword);
        disabledUser.setRole(Role.USER);
        disabledUser.setEnabled(false);
        userRepository.save(disabledUser);
        
        System.out.println("✅ Тестовые пользователи созданы:");
        System.out.println("   - admin:password (ADMIN)");
        System.out.println("   - user:password (USER)");
        System.out.println("   - testuser:password (USER)");
        System.out.println("   - testadmin:password (ADMIN)");
        System.out.println("   - lockeduser:password (USER, заблокирован)");
        System.out.println("   - disableduser:password (USER, отключен)");
    }
}
