package service

import (
	"context"
	"errors"
	"time"

	"github.com/arafinahmed/g-auth/internal/models"
	"github.com/arafinahmed/g-auth/internal/repository" // Assuming this path
	"github.com/arafinahmed/g-auth/pkg/auth"            // Assuming this path for JWT utils
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// AuthService defines the interface for authentication operations.
type AuthService interface {
	Register(ctx context.Context, email, password string) (*models.User, error)
	Login(ctx context.Context, email, password string) (accessToken, refreshToken string, err error)
	Logout(ctx context.Context, tokenString string) error
	Refresh(ctx context.Context, refreshTokenString string) (newAccessToken, newRefreshToken string, err error)
	ValidateAccessToken(tokenString string) (*auth.Claims, error)
}

// authService implements the AuthService interface.
type authServiceImpl struct {
	userRepo repository.UserRepository // Dependency on UserRepository interface
	redis    *redis.Client           // Dependency on Redis client
	jwtUtil  auth.JWTUtil              // Dependency on JWT utility
}

// NewAuthService creates a new instance of AuthService.
func NewAuthService(userRepo repository.UserRepository, redisClient *redis.Client, jwtUtil auth.JWTUtil) AuthService {
	return &authServiceImpl{
		userRepo: userRepo,
		redis:    redisClient,
		jwtUtil:  jwtUtil,
	}
}

// Register handles user registration.
func (s *authServiceImpl) Register(ctx context.Context, email, password string) (*models.User, error) {
	// Basic validation (more robust validation can be added)
	if email == "" || password == "" {
		return nil, errors.New("email and password cannot be empty")
	}

	// Check if user already exists
	_, err := s.userRepo.GetUserByEmail(ctx, email)
	if err == nil {
		return nil, errors.New("user with this email already exists")
	}
	if !errors.Is(err, repository.ErrUserNotFound) { // Check for unexpected DB errors
		return nil, err
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err // Consider logging this error
	}

	// Create user model
	user := &models.User{
		ID:       uuid.New(),
		Email:    email,
		Password: string(hashedPassword),
	}

	// Save user to database
	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, err // Consider logging this error
	}

	// Return user (without password)
	user.Password = ""
	return user, nil
}

// Login handles user login.
func (s *authServiceImpl) Login(ctx context.Context, email, password string) (string, string, error) {
	if email == "" || password == "" {
		return "", "", errors.New("email and password cannot be empty")
	}

	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return "", "", errors.New("invalid credentials")
		}
		return "", "", err // Other DB error
	}

	// Compare the provided password with the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", "", errors.New("invalid credentials") // Password doesn't match
	}

	// Generate tokens
	accessToken, refreshToken, err := s.jwtUtil.GenerateTokens(user.ID.String())
	if err != nil {
		return "", "", err // Token generation failed
	}

	return accessToken, refreshToken, nil
}

// Logout invalidates the provided access token by adding its JTI to the Redis blacklist.
func (s *authServiceImpl) Logout(ctx context.Context, tokenString string) error {
	claims, err := s.jwtUtil.ValidateToken(tokenString, auth.TokenTypeAccess) // Use the specific validation for access token type if needed
	if err != nil && !errors.Is(err, auth.ErrTokenExpired) { // Allow logging out with an expired token, but not invalid ones
		return errors.New("invalid token provided")
	}
	if claims == nil {
		// If validation failed but wasn't just expiry, we might still want to try parsing
		// to get the JTI, depending on security policy. Simpler to just return error here.
		// Alternatively, parse unverified to get JTI if absolutely needed.
		claims, _ = s.jwtUtil.ParseUnverified(tokenString)
		if claims == nil || claims.ID == "" {
			return errors.New("cannot extract JTI from token")
		}
	}

	jti := claims.ID
	expiresAt := claims.ExpiresAt.Time
	durationUntilExpiry := time.Until(expiresAt)

	// If the token is already expired, no need to blacklist, but logout is successful conceptually.
	if durationUntilExpiry <= 0 {
		return nil
	}

	// Add JTI to Redis blacklist with the remaining duration as TTL
	return s.redis.Set(ctx, "blacklist:"+jti, "revoked", durationUntilExpiry).Err()
}

// Refresh generates new access and refresh tokens based on a valid refresh token.
func (s *authServiceImpl) Refresh(ctx context.Context, refreshTokenString string) (string, string, error) {
	claims, err := s.jwtUtil.ValidateToken(refreshTokenString, auth.TokenTypeRefresh)
	if err != nil {
		return "", "", errors.New("invalid or expired refresh token")
	}

	// Check if the refresh token's JTI is blacklisted (optional, depends on strategy)
	// Usually, refresh tokens aren't blacklisted on logout, only access tokens.
	// If implementing refresh token rotation or single-use, blacklist check might be needed here.

	userID := claims.Subject

	// Generate new pair of tokens
	newAccessToken, newRefreshToken, err := s.jwtUtil.GenerateTokens(userID)
	if err != nil {
		return "", "", err
	}

	// Optional: Implement refresh token rotation
	// If rotating, blacklist the *used* refresh token JTI here.
	// err = s.redis.Set(ctx, "blacklist:"+claims.ID, "rotated", time.Until(claims.ExpiresAt.Time)).Err()
	// if err != nil { /* handle error */ }

	return newAccessToken, newRefreshToken, nil
}

// ValidateAccessToken checks if an access token is valid and not blacklisted.
func (s *authServiceImpl) ValidateAccessToken(tokenString string) (*auth.Claims, error) {
	claims, err := s.jwtUtil.ValidateToken(tokenString, auth.TokenTypeAccess)
	if err != nil {
		return nil, err // Covers expiry, signature, etc.
	}

	// Check Redis blacklist
	ctx := context.Background() // Or get from request context
	val, err := s.redis.Get(ctx, "blacklist:"+claims.ID).Result()
	if err == nil && val == "revoked" {
		return nil, auth.ErrTokenRevoked
	}
	if err != nil && err != redis.Nil {
		// Handle Redis error (e.g., log it)
		return nil, errors.New("error checking token blacklist")
	}

	// Token is valid and not blacklisted
	return claims, nil
}
