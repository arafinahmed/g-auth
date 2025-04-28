package main

import (
	"fmt"
	"log"
	"net/http"

	// Swagger UI
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/arafinahmed/g-auth/docs"

	"github.com/arafinahmed/g-auth/internal/config"
	"github.com/arafinahmed/g-auth/internal/db"
	"github.com/arafinahmed/g-auth/internal/handler"
	"github.com/arafinahmed/g-auth/internal/middleware"
	"github.com/arafinahmed/g-auth/internal/redis"
	"github.com/arafinahmed/g-auth/internal/repository"
	"github.com/arafinahmed/g-auth/internal/service"
	"github.com/arafinahmed/g-auth/pkg/auth"
)

func main() {
	log.Println("Starting authentication service...")

	// 1. Load Configuration
	// Consider using a flag or env var to specify .env path
	cfg, err := config.LoadConfig(".env") // Load from .env in the root directory
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize Database Connection
	postgresDB, err := db.NewPostgresDB(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer postgresDB.Close()

	// 3. Initialize Redis Client
	redisClient, err := redis.NewRedisClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	// 4. Initialize Dependencies
	userRepo := repository.NewPostgresUserRepository(postgresDB)
	jwtUtil, err := auth.NewJWTUtil(cfg.JWTSecret, cfg.JWTAccessTokenExpiryMin, cfg.JWTRefreshTokenExpiryDays)
	if err != nil {
		log.Fatalf("Failed to initialize JWT utility: %v", err)
	}
	authService := service.NewAuthService(userRepo, redisClient, jwtUtil)
	authHandler := handler.NewAuthHandler(authService)

	// 5. Setup HTTP Server and Routes
	mux := http.NewServeMux()

	// Serve Swagger UI
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	// --- Public Auth Routes ---
	mux.HandleFunc("/api/v1/auth/signup", authHandler.Signup)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("/api/v1/auth/logout", authHandler.Logout) // Needs JWT middleware if it operates on the token
	mux.HandleFunc("/api/v1/auth/refresh", authHandler.Refresh)

	// --- Protected Routes ---
	// Example protected route - requires valid JWT
	profileHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(middleware.UserIDKey)
		if userID == nil {
			// This should theoretically not happen if middleware is correct
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("User ID not found in context"))
			return
		}
		// Fetch user profile based on userID if needed
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"message": "Welcome to your profile!", "user_id": "%s"}`, userID)))
	})

	// Apply middleware to the protected handler
	protectedProfileHandler := middleware.JWTMiddleware(authService)(profileHandler)
	mux.Handle("/api/v1/profile", protectedProfileHandler)

	// Health check endpoint (optional)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// --- Start Server ---
	serverAddr := ":" + cfg.ServerPort
	log.Printf("Server starting on %s", serverAddr)

	server := &http.Server{
		Addr:    serverAddr,
		Handler: mux, // Add logging/CORS middleware here if needed
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", serverAddr, err)
	}

	log.Println("Server stopped.")
}
