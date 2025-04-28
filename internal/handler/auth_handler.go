package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/arafinahmed/g-auth/internal/service"
)

// AuthHandler holds the authentication service dependency.
type AuthHandler struct {
	service service.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{service: authService}
}

// --- Request/Response Structs ---

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- Handlers ---

// Signup handles user registration requests.
// @Summary Register a new user
// @Description Registers a new user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param signupRequest body signupRequest true "User signup data"
// @Success 201 {object} models.User
// @Failure 400 {object} errorResponse
// @Failure 409 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /api/v1/auth/signup [post]
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	user, err := h.service.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		// Log the actual error for debugging
		log.Printf("Register error: %v", err)
		// Check for specific user-facing errors (e.g., already exists)
		if strings.Contains(err.Error(), "already exists") {
			respondWithError(w, http.StatusConflict, err.Error())
		} else {
			respondWithError(w, http.StatusInternalServerError, "Failed to register user")
		}
		return
	}

	// Omit sensitive data from response if necessary (password already omitted by service)
	respondWithJSON(w, http.StatusCreated, user)
}

// Login handles user login requests.
// @Summary Login user
// @Description Authenticates user and returns access and refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param loginRequest body loginRequest true "User login data"
// @Success 200 {object} loginResponse
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	accessToken, refreshToken, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "invalid credentials") {
			respondWithError(w, http.StatusUnauthorized, err.Error())
		} else {
			respondWithError(w, http.StatusInternalServerError, "Login failed")
		}
		return
	}

	resp := loginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	respondWithJSON(w, http.StatusOK, resp)

	// Note: Consider setting Refresh Token in an HttpOnly cookie for better security
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "refresh_token",
	// 	Value:    refreshToken,
	// 	HttpOnly: true,
	// 	Secure:   true, // Set to true in production with HTTPS
	// 	Path:     "/api/v1/auth/refresh", // Limit scope
	// 	Expires:  time.Now().Add(time.Hour * 24 * 7), // Match token expiry
	// 	SameSite: http.SameSiteLaxMode,
	// })
}

// Logout handles user logout requests.
// @Summary Logout user
// @Description Logs out the user and invalidates the token
// @Tags auth
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} map[string]string
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, http.StatusUnauthorized, "Authorization header missing or invalid")
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	err := h.service.Logout(r.Context(), tokenString)
	if err != nil {
		// Differentiate between bad token and internal error if needed
		respondWithError(w, http.StatusInternalServerError, "Logout failed")
		return
	}

	// Also clear the refresh token cookie if used
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "refresh_token",
	// 	Value:    "",
	// 	HttpOnly: true,
	// 	Secure:   true,
	// 	Path:     "/api/v1/auth/refresh",
	// 	Expires:  time.Unix(0, 0), // Expire immediately
	// })

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Successfully logged out"})
}

// Refresh handles token refresh requests.
// @Summary Refresh token
// @Description Generates new access and refresh tokens using a valid refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param refreshRequest body refreshRequest true "Refresh token data"
// @Success 200 {object} loginResponse
// @Failure 400 {object} errorResponse
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req refreshRequest
	// Try reading from body first
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If body is empty or invalid, try reading from cookie
		cookie, err := r.Cookie("refresh_token")
		if err != nil || cookie.Value == "" {
			respondWithError(w, http.StatusBadRequest, "Refresh token missing in body or cookie")
			return
		}
		req.RefreshToken = cookie.Value
	}
	defer r.Body.Close()

	if req.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "Refresh token cannot be empty")
		return
	}

	newAccessToken, newRefreshToken, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Failed to refresh token: "+err.Error())
		return
	}

	resp := loginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}

	// If using cookies, update the refresh token cookie here as well
	// http.SetCookie(w, &http.Cookie{... with newRefreshToken ...})

	respondWithJSON(w, http.StatusOK, resp)
}

// --- Helper Functions ---

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, errorResponse{Error: message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to marshal JSON response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
