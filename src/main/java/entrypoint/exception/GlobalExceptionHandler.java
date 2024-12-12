package entrypoint.exception;

import entrypoint.dto.ApiResponseDTO;
import jakarta.mail.MessagingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ControllerAdvice;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO> handleException(Exception e) {
        ApiResponseDTO response = ApiResponseDTO.errorResponse("Internal Server Error", e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponseDTO> handleIllegalArgumentException(IllegalArgumentException e) {
        ApiResponseDTO response = ApiResponseDTO.errorResponse("Invalid Argument", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDTO> handleValidationException(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));
        ApiResponseDTO errorResponse = ApiResponseDTO.errorResponse("Validation failed!", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    public static class EmailAlreadyExistsException extends RuntimeException {
        public EmailAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    public static class InvalidUserException extends RuntimeException {
        public InvalidUserException(String message) {
            super(message);
        }
    }

    public static class InvalidPasswordException extends RuntimeException {
        public InvalidPasswordException(String message) {
            super(message);
        }
    }

    public static class ExpiredOTPException extends RuntimeException {
        public ExpiredOTPException(String message) {
            super(message);
        }
    }

    public static class InvalidOTPException extends RuntimeException {
        public InvalidOTPException(String message) {
            super(message);
        }
    }

    public static class FailedToSendMailException extends MessagingException {
        public FailedToSendMailException(String message) {
            super(message);
        }
    }

    public static class EmailExtractionFailedException extends RuntimeException {
        public EmailExtractionFailedException(String message) {
            super(message);
        }
    }

    public static class ExpiredJwtException extends RuntimeException {
        public ExpiredJwtException(String message) {
            super(message);
        }
    }
}
