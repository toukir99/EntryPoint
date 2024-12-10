package EntryPoint.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@RequiredArgsConstructor
@Component
public class OTPUtil {
    private final StringRedisTemplate redisTemplate;

    public String generateOTP(String email){
        SecureRandom secureRandom = new SecureRandom();
        String otp;

        do {
            otp = String.format("%04d", secureRandom.nextInt(10000));
        } while (redisTemplate.hasKey(email));

        return otp;
    }
}
