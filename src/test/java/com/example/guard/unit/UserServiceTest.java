package com.example.guard.unit;

import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.repository.UserRepository;
import com.example.guard.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @InjectMocks
    private UserService userService;
    
    private User testUser;
    private User testAdmin;
    
    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("encodedPassword");
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);
        testUser.setLastLogin(LocalDateTime.now());
        testUser.setLoginAttempts(0);
        testUser.setLockedUntil(null);
        
        testAdmin = new User();
        testAdmin.setId(2L);
        testAdmin.setUsername("testadmin");
        testAdmin.setPassword("encodedPassword");
        testAdmin.setRole(Role.ADMIN);
        testAdmin.setEnabled(true);
        testAdmin.setLastLogin(LocalDateTime.now());
        testAdmin.setLoginAttempts(0);
        testAdmin.setLockedUntil(null);
    }
    
    @Test
    void testCreateUser_Success() {
        // Given
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(passwordEncoder.encode("password")).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        User result = userService.createUser("newuser", "password", Role.USER);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRole()).isEqualTo(Role.USER);
        assertThat(result.isEnabled()).isTrue();
        
        verify(userRepository).existsByUsername("newuser");
        verify(passwordEncoder).encode("password");
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    void testCreateUser_UsernameAlreadyExists() {
        // Given
        when(userRepository.existsByUsername("existinguser")).thenReturn(true);
        
        // When & Then
        assertThatThrownBy(() -> userService.createUser("existinguser", "password", Role.USER))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Username already exists: existinguser");
        
        verify(userRepository).existsByUsername("existinguser");
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    void testFindByUsername_Success() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        
        // When
        Optional<User> result = userService.findByUsername("testuser");
        
        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("testuser");
        assertThat(result.get().getRole()).isEqualTo(Role.USER);
        
        verify(userRepository).findByUsername("testuser");
    }
    
    @Test
    void testFindByUsername_NotFound() {
        // Given
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());
        
        // When
        Optional<User> result = userService.findByUsername("nonexistent");
        
        // Then
        assertThat(result).isEmpty();
        
        verify(userRepository).findByUsername("nonexistent");
    }
    
    @Test
    void testGetAllUsers() {
        // Given
        List<User> users = Arrays.asList(testUser, testAdmin);
        when(userRepository.findAll()).thenReturn(users);
        
        // When
        List<com.example.guard.dto.UserDto> result = userService.getAllUsers();
        
        // Then
        assertThat(result).hasSize(2);
        assertThat(result.get(0).getUsername()).isEqualTo("testuser");
        assertThat(result.get(1).getUsername()).isEqualTo("testadmin");
        
        verify(userRepository).findAll();
    }
    
    @Test
    void testGetUsersByRole() {
        // Given
        List<User> users = Arrays.asList(testUser);
        when(userRepository.findAll()).thenReturn(Arrays.asList(testUser, testAdmin));
        
        // When
        List<com.example.guard.dto.UserDto> result = userService.getUsersByRole(Role.USER);
        
        // Then
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getUsername()).isEqualTo("testuser");
        assertThat(result.get(0).getRole()).isEqualTo(Role.USER);
        
        verify(userRepository).findAll();
    }
    
    @Test
    void testDeleteUser_Success() {
        // Given
        when(userRepository.existsById(1L)).thenReturn(true);
        
        // When
        userService.deleteUser(1L);
        
        // Then
        verify(userRepository).existsById(1L);
        verify(userRepository).deleteById(1L);
    }
    
    @Test
    void testDeleteUser_NotFound() {
        // Given
        when(userRepository.existsById(999L)).thenReturn(false);
        
        // When & Then
        assertThatThrownBy(() -> userService.deleteUser(999L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("User not found with id: 999");
        
        verify(userRepository).existsById(999L);
        verify(userRepository, never()).deleteById(any());
    }
    
    @Test
    void testToggleUserStatus() {
        // Given
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        userService.toggleUserStatus(1L);
        
        // Then
        verify(userRepository).findById(1L);
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    void testUpdateLastLogin() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        userService.updateLastLogin("testuser");
        
        // Then
        verify(userRepository).findByUsername("testuser");
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    void testIncrementLoginAttempts() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        userService.incrementLoginAttempts("testuser");
        
        // Then
        verify(userRepository).findByUsername("testuser");
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    void testGetUserStats() {
        // Given
        when(userRepository.count()).thenReturn(10L);
        when(userRepository.countByRole(Role.ADMIN)).thenReturn(2L);
        when(userRepository.countByRole(Role.USER)).thenReturn(8L);
        
        // When
        UserService.UserStats stats = userService.getUserStats();
        
        // Then
        assertThat(stats.getTotalUsers()).isEqualTo(10L);
        assertThat(stats.getAdminCount()).isEqualTo(2L);
        assertThat(stats.getUserCount()).isEqualTo(8L);
        
        verify(userRepository).count();
        verify(userRepository).countByRole(Role.ADMIN);
        verify(userRepository).countByRole(Role.USER);
    }
}
