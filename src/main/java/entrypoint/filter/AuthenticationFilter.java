package entrypoint.filter;

import entrypoint.dto.ApiResponseDTO;
import entrypoint.exception.GlobalExceptionHandler.*;
import entrypoint.utils.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTH_HEADER = "Authorization";
    private static final String REFRESH_TOKEN_HEADER = "Refresh-Token";
    private static final String FORBIDDEN_MESSAGE = "Token has been invalidated. Please login again.";
    private static final String MISSING_AUTH_HEADER_MESSAGE = "Authorization header missing or invalid!";
    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/register",
            "/api/v1/auth/verify-otp",
            "/api/v1/auth/login"
    };

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        // Skip authentication for public endpoints
        if (isPublicEndpoint(requestURI)) {
            filterChain.doFilter(request, response); // Continue the filter chain for public routes
            return;
        }

        String authHeader = request.getHeader(AUTH_HEADER);
        String refreshTokenHeader = request.getHeader(REFRESH_TOKEN_HEADER);

        // Validate tokens
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String accessToken = extractToken(authHeader);
            String refreshToken = refreshTokenHeader != null && refreshTokenHeader.startsWith(BEARER_PREFIX)
                    ? extractToken(refreshTokenHeader)
                    : null;

            try {
                processTokens(response, accessToken, refreshToken);
            } catch (SecurityException e) {
                sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
                return;
            }
        } else {
            sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, MISSING_AUTH_HEADER_MESSAGE);
            return;
        }

        // Proceed with the request
        filterChain.doFilter(request, response);
    }

    private String extractToken(String header) {
        return header.substring(BEARER_PREFIX.length()).trim();
    }

    private void processTokens(HttpServletResponse response, String accessToken, String refreshToken)
            throws SecurityException, IOException {

        if (jwtUtil.validateToken(accessToken)) {
            sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, FORBIDDEN_MESSAGE);
            throw new SecurityException(FORBIDDEN_MESSAGE);
        }

        if (refreshToken != null && jwtUtil.validateToken(refreshToken)) {
            sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, FORBIDDEN_MESSAGE);
            throw new SecurityException(FORBIDDEN_MESSAGE);
        }

        String email = jwtUtil.extractEmail(accessToken);
        if(email != null) {
            setAuthentication(email);
        } else {
            throw new EmailExtractionFailedException("Email Extraction Failed!");
        }
    }

    private void setAuthentication(String email) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(email, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message) throws IOException {
        ApiResponseDTO errorResponse = ApiResponseDTO.errorResponse(message, null);

        // Convert ApiResponseDTO to JSON
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);

        response.setStatus(statusCode);
        response.setContentType("application/json");
        response.getWriter().write(jsonResponse); // Write JSON response to output stream
    }

    private boolean isPublicEndpoint(String requestURI) {
        for (String publicEndpoint : PUBLIC_ENDPOINTS) {
            if (requestURI.startsWith(publicEndpoint)) {
                return true;
            }
        }
        return false;
    }
}
