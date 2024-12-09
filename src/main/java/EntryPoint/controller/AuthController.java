package EntryPoint.controller;

import EntryPoint.dto.ApiResponseDTO;
import EntryPoint.dto.UserDTO;
import EntryPoint.exception.GlobalExceptionHandler.*;
import EntryPoint.service.UserService;
import EntryPoint.utils.JwtUtil;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import EntryPoint.exception.GlobalExceptionHandler.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    ApiResponseDTO response;

    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO> register(@Valid @RequestBody UserDTO request) {
        try {
            Object registeredEmail = userService.register(request);
            response = new ApiResponseDTO(true, "Registration Successful", registeredEmail);
            return ResponseEntity.ok(response);
        } catch (EmailAlreadyTakenException e) {
            ApiResponseDTO response = ApiResponseDTO.errorResponse("Registration Failed", e.getMessage());
            return ResponseEntity.status(400).body(response);
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("Registration Failed", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponseDTO> verifyOTP(@RequestParam String email, @RequestParam String otp) {
        try {
            userService.verifyOTP(email, otp);
            response = new ApiResponseDTO(true, "OTP is verified successfully and registration is completed successfully", null);
            return ResponseEntity.ok(response);
        } catch (ExpiredOTPException ex) {
            response = ApiResponseDTO.errorResponse("OTP has expired!", ex.getMessage());
            return ResponseEntity.status(400).body(response);
        } catch (InvalidOTPException ex) {
            response = ApiResponseDTO.errorResponse("Invalid OTP!", ex.getMessage());
            return ResponseEntity.status(400).body(response);
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("OTP verification failed!", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }


    @PostMapping("/login")
    public ResponseEntity<ApiResponseDTO> login(@Valid @RequestBody UserDTO request) {
        try {
            Object token = userService.login(request);
            response = new ApiResponseDTO(true, "You are logged in!", token);
            return ResponseEntity.ok(response);
        } catch (InvalidUserException ex) {
            response = ApiResponseDTO.errorResponse("User is not verified!", ex.getMessage());
            return ResponseEntity.status(400).body(response);
        } catch (InvalidPasswordException e) {
            response = ApiResponseDTO.errorResponse("Invalid Credentials!", e.getMessage());
            return ResponseEntity.status(400).body(response);
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("Login Failed", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDTO> getUserProfile(@RequestHeader("Authorization") String accessToken) {
        try {
            String token = jwtUtil.extractToken(accessToken);
            String email = jwtUtil.extractEmail(token);
            Object profile = userService.getProfile(email);
            response = new ApiResponseDTO(true, "User Profile", profile);
            return ResponseEntity.ok(response);
        } catch (UserNotFoundException e) {
            response = ApiResponseDTO.errorResponse("User not found!", e.getMessage());
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("Profile fetching failed!", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponseDTO> refreshJwtToken(@RequestHeader("Authorization") String refreshToken) {
        try {
            String token = jwtUtil.extractToken(refreshToken);
            Object newAccessToken = userService.refreshJwtToken(token);
            response = new ApiResponseDTO(true, "Access Token refreshed", newAccessToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("Failed to refresh token!", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO> logoutUser(@RequestHeader("Authorization") String accessToken, @RequestHeader("Refresh-Token") String refreshToken) {
        try {
            accessToken = jwtUtil.extractToken(accessToken);
            refreshToken = jwtUtil.extractToken(refreshToken);

            boolean isLoggedOut = userService.logout(accessToken, refreshToken);
            if(isLoggedOut){
                response = new ApiResponseDTO(true, "Logout successful", null);
                return ResponseEntity.ok(response);
            } else {
                response = ApiResponseDTO.errorResponse("Logout Failed!", null);
                return ResponseEntity.status(400).body(response);
            }
        } catch (Exception e) {
            response = ApiResponseDTO.errorResponse("Logout Failed", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
}
