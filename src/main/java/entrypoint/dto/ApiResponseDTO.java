package entrypoint.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.time.Instant;

@Data
@AllArgsConstructor
public class ApiResponseDTO {
    private Instant timestamp;
    private boolean status;
    private String message;
    private Object data;
    private Object errors;

    public ApiResponseDTO(boolean status, String message, Object data) {
        this.timestamp = Instant.now();
        this.status = status;
        this.message = message;
        this.data = data;
        this.errors = null;
    }

    public static ApiResponseDTO errorResponse(String message, Object errors) {
        return new ApiResponseDTO(Instant.now(), false, message, null, errors);
    }
}
