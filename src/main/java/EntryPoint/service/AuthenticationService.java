package EntryPoint.service;

import EntryPoint.dto.AccessTokenResponseDTO;
import EntryPoint.dto.LoginResponseDTO;
import EntryPoint.dto.UserDTO;
import EntryPoint.dto.UserProfileDTO;
import EntryPoint.exception.GlobalExceptionHandler.*;
import EntryPoint.repository.UserRepository;
import EntryPoint.utils.JwtUtil;
import EntryPoint.utils.OTPUtil;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import EntryPoint.model.User;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor

public class AuthenticationService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final OTPUtil otpUtil;
    private final StringRedisTemplate redisTemplate;
    private final EmailService emailService;

    public Object registerUser(UserDTO request) throws MessagingException {
        String email = request.getEmail();
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailAlreadyExistsException("Email is already taken!");
        }
        String otp = otpUtil.generateOTP(email);

        int ttl = 2;
        redisTemplate.opsForValue().set(email, otp, ttl, TimeUnit.MINUTES);

        emailService.sendOTP(request.getEmail(), otp);
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .isActive(false)
                .build();
        userRepository.save(user);
        return email;
    }

    public void verifyOTP(String email, String otp) {
        String storedOTP = redisTemplate.opsForValue().get(email);
        System.out.println(storedOTP);

        if (storedOTP == null) {
            throw new ExpiredOTPException("OTP has expired!");
        }

        if (!storedOTP.equals(otp)) {
            throw new InvalidOTPException("Invalid OTP. Please try again.");
        }

        redisTemplate.delete(email);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found!"));
        user.setIsActive(true);
        userRepository.save(user);
    }

    public Object loginUser(UserDTO request) {
        User user = userRepository.findByEmail(request.getEmail())
                        .orElseThrow(() -> new UserNotFoundException("Invalid user!"));

        if(!user.getIsActive()) {
            throw new InvalidUserException("User is not active. Please validate your OTP before logging in.");
        }

        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new InvalidPasswordException("Invalid password!");
        }

        String accessToken = jwtUtil.generateAccessToken(user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        return new LoginResponseDTO(user.getEmail(), accessToken, refreshToken);
    }

    public Object getProfileUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found!"));
        return new UserProfileDTO(user.getEmail());
    }

    public Object refreshAccessToken(String refreshToken) {
        String email = jwtUtil.extractEmail(refreshToken);
        String newAccessToken = jwtUtil.generateAccessToken(email);
        return new AccessTokenResponseDTO(newAccessToken);
    }

    public boolean logoutUser(String accessToken, String refreshToken) {
        jwtUtil.invalidateToken(accessToken);
        jwtUtil.invalidateToken(refreshToken);
        return true;
    }
}
