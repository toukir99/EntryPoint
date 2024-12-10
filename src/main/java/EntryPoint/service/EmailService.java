package EntryPoint.service;

import EntryPoint.exception.GlobalExceptionHandler.FailedToSendMailException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendOTP(String toEmail, String otp) throws MessagingException {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(toEmail);
            helper.setSubject("OTP Code");
            helper.setText("Your OTP code is: " + otp, true);

            mailSender.send(message);
        } catch (FailedToSendMailException e) {
            throw new FailedToSendMailException("Failed to send mail");
        }
    }
}
