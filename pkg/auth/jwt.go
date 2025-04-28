package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Define standard JWT errors
var (
	ErrTokenInvalid = errors.New("token is invalid")
	ErrTokenExpired = errors.New("token has expired")
	ErrTokenRevoked = errors.New("token has been revoked") // Specific error for blacklist check
)

// TokenType differentiates between access and refresh tokens
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Claims represents the JWT claims specific to this application.
type Claims struct {
	Type TokenType `json:"type"` // Differentiate token type
	jwt.RegisteredClaims
}

// JWTUtil defines the interface for JWT operations.
// This helps in mocking for tests.
type JWTUtil interface {
	GenerateTokens(userID string) (accessToken string, refreshToken string, err error)
	ValidateToken(tokenString string, expectedType TokenType) (*Claims, error)
	ParseUnverified(tokenString string) (*Claims, error) // To extract JTI even if token is expired
}

// jwtUtilImpl implements the JWTUtil interface.
type jwtUtilImpl struct {
	secretKey          []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// NewJWTUtil creates a new JWTUtil instance.
func NewJWTUtil(secret string, accessExpiryMinutes, refreshExpiryDays int) (JWTUtil, error) {
	if secret == "" {
		return nil, errors.New("JWT secret cannot be empty")
	}
	return &jwtUtilImpl{
		secretKey:          []byte(secret),
		accessTokenExpiry:  time.Minute * time.Duration(accessExpiryMinutes),
		refreshTokenExpiry: time.Hour * 24 * time.Duration(refreshExpiryDays),
	}, nil
}

// GenerateTokens creates new access and refresh tokens for a given user ID.
func (j *jwtUtilImpl) GenerateTokens(userID string) (string, string, error) {
	accessToken, err := j.generateToken(userID, TokenTypeAccess, j.accessTokenExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := j.generateToken(userID, TokenTypeRefresh, j.refreshTokenExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// generateToken is a helper to create a specific type of token.
func (j *jwtUtilImpl) generateToken(userID string, tokenType TokenType, expiryDuration time.Duration) (string, error) {
	claims := &Claims{
		Type: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiryDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(), // JTI (JWT ID) for tracking/revocation
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// ValidateToken parses and validates a token string.
func (j *jwtUtilImpl) ValidateToken(tokenString string, expectedType TokenType) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return claims, ErrTokenExpired // Return claims even if expired, for JTI extraction if needed
		}
		return nil, ErrTokenInvalid
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	// Check if the token type matches the expected type
	if claims.Type != expectedType {
		return nil, fmt.Errorf("token type mismatch: expected %s, got %s", expectedType, claims.Type)
	}

	return claims, nil
}

// ParseUnverified extracts claims without verifying the signature or expiry.
// Useful for getting JTI from an expired token during logout.
func (j *jwtUtilImpl) ParseUnverified(tokenString string) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.Parser{}
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token unverified: %w", err)
	}
	return claims, nil
}
