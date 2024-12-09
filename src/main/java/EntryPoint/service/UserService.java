package EntryPoint.service;

import EntryPoint.dto.AccessTokenResponseDTO;
import EntryPoint.dto.LoginResponseDTO;
import EntryPoint.dto.UserDTO;
import EntryPoint.dto.UserProfileDTO;
import EntryPoint.exception.GlobalExceptionHandler.*;
import EntryPoint.repository.UserRepository;
import EntryPoint.utils.JwtUtil;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import EntryPoint.model.User;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor

public class UserService {
    @Autowired
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final StringRedisTemplate redisTemplate;

    public Object register(UserDTO request) throws MessagingException {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyTakenException("Email is already taken!");
        }

        String otp = String.format("%06d", new Random().nextInt(999999));

        redisTemplate.opsForValue().set(request.getEmail(), otp, 3, TimeUnit.MINUTES);

        emailService.sendOTP(request.getEmail(), otp);
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .isActive(false)
                .build();
        userRepository.save(user);
        return user.getEmail();
    }

    public void verifyOTP(String email, String otp) {
        String storedOTP = redisTemplate.opsForValue().get(email);

        if (storedOTP == null) {
            throw new ExpiredOTPException("OTP has expired. Please request a new OTP.");
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

    public Object login(UserDTO request) {
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

    public Object getProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found!"));
        return new UserProfileDTO(user.getEmail());
    }

    public Object refreshJwtToken(String refreshToken) {
        String email = jwtUtil.extractEmail(refreshToken);
        String newAccessToken = jwtUtil.generateAccessToken(email);
        return new AccessTokenResponseDTO(newAccessToken);
    }

    public boolean logout(String accessToken, String refreshToken) {
        jwtUtil.invalidateToken(accessToken);
        jwtUtil.invalidateToken(refreshToken);
        return true;
    }
}
