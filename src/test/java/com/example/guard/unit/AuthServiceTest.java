package com.example.guard.unit;

import com.example.guard.dto.LoginRequest;
import com.example.guard.dto.LoginResponse;
import com.example.guard.entity.Role;
import com.example.guard.entity.User;
import com.example.guard.service.AuthService;
import com.example.guard.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    
    @Mock
    private UserService userService;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @InjectMocks
    private AuthService authService;
    
    private User testUser;
    private User testAdmin;
    private LoginRequest validLoginRequest;
    private LoginRequest invalidLoginRequest;
    
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
        
        validLoginRequest = new LoginRequest("testuser", "password");
        invalidLoginRequest = new LoginRequest("testuser", "wrongpassword");
    }
    
    @Test
    void testAuthenticate_Success() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password", "encodedPassword")).thenReturn(true);
        
        // When
        LoginResponse response = authService.authenticate(validLoginRequest);
        
        // Then
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getUsername()).isEqualTo("testuser");
        assertThat(response.getRole()).isEqualTo(Role.USER);
        assertThat(response.getMessage()).isEqualTo("Login successful");
        
        verify(userService).findByUsername("testuser");
        verify(passwordEncoder).matches("password", "encodedPassword");
        verify(userService).updateLastLogin("testuser");
    }
    
    @Test
    void testAuthenticate_UserNotFound() {
        // Given
        when(userService.findByUsername("nonexistent")).thenReturn(Optional.empty());
        
        LoginRequest request = new LoginRequest("nonexistent", "password");
        
        // When
        LoginResponse response = authService.authenticate(request);
        
        // Then
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Invalid username or password");
        assertThat(response.getUsername()).isNull();
        assertThat(response.getRole()).isNull();
        
        verify(userService).findByUsername("nonexistent");
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(userService, never()).updateLastLogin(anyString());
    }
    
    @Test
    void testAuthenticate_WrongPassword() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrongpassword", "encodedPassword")).thenReturn(false);
        
        // When
        LoginResponse response = authService.authenticate(invalidLoginRequest);
        
        // Then
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Invalid username or password");
        assertThat(response.getUsername()).isNull();
        assertThat(response.getRole()).isNull();
        
        verify(userService).findByUsername("testuser");
        verify(passwordEncoder).matches("wrongpassword", "encodedPassword");
        verify(userService).incrementLoginAttempts("testuser");
        verify(userService, never()).updateLastLogin(anyString());
    }
    
    @Test
    void testAuthenticate_AccountLocked() {
        // Given
        User lockedUser = new User();
        lockedUser.setUsername("lockeduser");
        lockedUser.setPassword("encodedPassword");
        lockedUser.setRole(Role.USER);
        lockedUser.setEnabled(true);
        lockedUser.setLockedUntil(LocalDateTime.now().plusMinutes(15));
        
        when(userService.findByUsername("lockeduser")).thenReturn(Optional.of(lockedUser));
        
        LoginRequest request = new LoginRequest("lockeduser", "password");
        
        // When
        LoginResponse response = authService.authenticate(request);
        
        // Then
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Account is locked. Try again later.");
        
        verify(userService).findByUsername("lockeduser");
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(userService, never()).updateLastLogin(anyString());
    }
    
    @Test
    void testAuthenticate_AccountDisabled() {
        // Given
        User disabledUser = new User();
        disabledUser.setUsername("disableduser");
        disabledUser.setPassword("encodedPassword");
        disabledUser.setRole(Role.USER);
        disabledUser.setEnabled(false);
        
        when(userService.findByUsername("disableduser")).thenReturn(Optional.of(disabledUser));
        
        LoginRequest request = new LoginRequest("disableduser", "password");
        
        // When
        LoginResponse response = authService.authenticate(request);
        
        // Then
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Account is disabled");
        
        verify(userService).findByUsername("disableduser");
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(userService, never()).updateLastLogin(anyString());
    }
    
    @Test
    void testHasPermission_AdminRole() {
        // Given
        when(userService.findByUsername("testadmin")).thenReturn(Optional.of(testAdmin));
        
        // When
        boolean hasPermission = authService.hasPermission("testadmin", "ADMIN");
        
        // Then
        assertThat(hasPermission).isTrue();
        
        verify(userService).findByUsername("testadmin");
    }
    
    @Test
    void testHasPermission_UserRole() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        
        // When
        boolean hasPermission = authService.hasPermission("testuser", "USER");
        
        // Then
        assertThat(hasPermission).isTrue();
        
        verify(userService).findByUsername("testuser");
    }
    
    @Test
    void testHasPermission_AdminCanAccessUserRole() {
        // Given
        when(userService.findByUsername("testadmin")).thenReturn(Optional.of(testAdmin));
        
        // When
        boolean hasPermission = authService.hasPermission("testadmin", "USER");
        
        // Then
        assertThat(hasPermission).isTrue();
        
        verify(userService).findByUsername("testadmin");
    }
    
    @Test
    void testHasPermission_UserCannotAccessAdminRole() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        
        // When
        boolean hasPermission = authService.hasPermission("testuser", "ADMIN");
        
        // Then
        assertThat(hasPermission).isFalse();
        
        verify(userService).findByUsername("testuser");
    }
    
    @Test
    void testHasPermission_UserNotFound() {
        // Given
        when(userService.findByUsername("nonexistent")).thenReturn(Optional.empty());
        
        // When
        boolean hasPermission = authService.hasPermission("nonexistent", "USER");
        
        // Then
        assertThat(hasPermission).isFalse();
        
        verify(userService).findByUsername("nonexistent");
    }
    
    @Test
    void testHasPermission_UserDisabled() {
        // Given
        User disabledUser = new User();
        disabledUser.setUsername("disableduser");
        disabledUser.setRole(Role.USER);
        disabledUser.setEnabled(false);
        
        when(userService.findByUsername("disableduser")).thenReturn(Optional.of(disabledUser));
        
        // When
        boolean hasPermission = authService.hasPermission("disableduser", "USER");
        
        // Then
        assertThat(hasPermission).isFalse();
        
        verify(userService).findByUsername("disableduser");
    }
    
    @Test
    void testIsAdmin() {
        // Given
        when(userService.findByUsername("testadmin")).thenReturn(Optional.of(testAdmin));
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        
        // When & Then
        assertThat(authService.isAdmin("testadmin")).isTrue();
        assertThat(authService.isAdmin("testuser")).isFalse();
        
        verify(userService, times(2)).findByUsername(anyString());
    }
    
    @Test
    void testIsUser() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(userService.findByUsername("testadmin")).thenReturn(Optional.of(testAdmin));
        
        // When & Then
        assertThat(authService.isUser("testuser")).isTrue();
        assertThat(authService.isUser("testadmin")).isFalse();
        
        verify(userService, times(2)).findByUsername(anyString());
    }
    
    @Test
    void testGetUserInfo() {
        // Given
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        
        // When
        User result = authService.getUserInfo("testuser");
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getRole()).isEqualTo(Role.USER);
        
        verify(userService).findByUsername("testuser");
    }
}

