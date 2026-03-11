// ═══════════════════════════════════════════════════════════════════════════
//  DocFlow — Go + Fiber Backend
//  Production-quality REST API
//  Roles: USER | CONTROLLER | ADMIN
// ═══════════════════════════════════════════════════════════════════════════
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ─── GLOBALS ──────────────────────────────────────────────────────────────────

var (
	db        *pgxpool.Pool
	jwtSecret []byte
	pdfAPI    string // http://pdf-service:8000
)

const (
	RoleUser       = "USER"
	RoleController = "CONTROLLER"
	RoleAdmin      = "ADMIN"

	StatusPending  = "PENDING"
	StatusApproved = "APPROVED"
	StatusRejected = "REJECTED"
	StatusArchived = "ARCHIVED"
	StatusDeleted  = "DELETED"

	FileActive   = "ACTIVE"
	FileArchived = "ARCHIVED"
	FileDeleted  = "DELETED"
)

// ─── MODELS ───────────────────────────────────────────────────────────────────

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Surname   string    `json:"surname"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type File struct {
	ID           string    `json:"id"`
	OriginalName string    `json:"original_name"`
	SizeBytes    int64     `json:"size_bytes"`
	UploadedBy   string    `json:"uploaded_by"`
	PdfSessionID string    `json:"pdf_session_id"`
	ModSessionID string    `json:"mod_session_id"`
	Status       string    `json:"status"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type Ticket struct {
	ID           string          `json:"id"`
	FileID       string          `json:"file_id"`
	FileName     string          `json:"file_name"`
	RequesterID  string          `json:"requester_id"`
	RequesterEmail string        `json:"requester_email"`
	ControllerID string          `json:"controller_id"`
	ControllerEmail string       `json:"controller_email"`
	Status       string          `json:"status"`
	Changes      json.RawMessage `json:"changes"`
	EditPayload  json.RawMessage `json:"edit_payload,omitempty"`
	Note         string          `json:"note"`
	RejectReason string          `json:"reject_reason"`
	CreatedAt    time.Time       `json:"created_at"`
	ResolvedAt   *time.Time      `json:"resolved_at,omitempty"`
	ExpiresAt    time.Time       `json:"expires_at"`
	PdfSessionID string          `json:"pdf_session_id"`
	ModSessionID string          `json:"mod_session_id"`
}

type AuditLog struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Icon      string    `json:"icon"`
	Msg       string    `json:"msg"`
	Detail    string    `json:"detail"`
	UserEmail string    `json:"user_email"`
	CreatedAt time.Time `json:"created_at"`
}

type SMTPConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Sec          string `json:"sec"`
	User         string `json:"user"`
	Pw           string `json:"pw"`
	From         string `json:"from"`
	OTPEnabled   bool   `json:"otp_enabled"`
	NotifEnabled bool   `json:"notif_enabled"`
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// ─── DATABASE ─────────────────────────────────────────────────────────────────

func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	var err error
	db, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("DB connection failed: %v", err)
	}
	// Ping
	if err = db.Ping(context.Background()); err != nil {
		log.Fatalf("DB ping failed: %v", err)
	}
	log.Println("✅ PostgreSQL connected")
}

func runMigrations() {
	data, err := os.ReadFile("/app/migrations/001_init.sql")
	if err != nil {
		log.Fatalf("Migration file not found: %v", err)
	}
	_, err = db.Exec(context.Background(), string(data))
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	log.Println("✅ Migrations applied")
}

// ─── CONFIG HELPERS ───────────────────────────────────────────────────────────

func getConfig(key string) string {
	var val string
	db.QueryRow(context.Background(),
		`SELECT value FROM app_config WHERE key=$1`, key).Scan(&val)
	return val
}

func setConfig(key, value string) {
	db.Exec(context.Background(),
		`INSERT INTO app_config(key,value,updated_at) VALUES($1,$2,NOW())
         ON CONFLICT(key) DO UPDATE SET value=$2, updated_at=NOW()`, key, value)
}

func getSMTPConfig() SMTPConfig {
	port, _ := strconv.Atoi(getConfig("smtp_port"))
	if port == 0 {
		port = 587
	}
	return SMTPConfig{
		Host:         getConfig("smtp_host"),
		Port:         port,
		Sec:          getConfig("smtp_sec"),
		User:         getConfig("smtp_user"),
		Pw:           getConfig("smtp_pw"),
		From:         getConfig("smtp_from"),
		OTPEnabled:   getConfig("smtp_otp_enabled") != "false",
		NotifEnabled: getConfig("smtp_notif_enabled") != "false",
	}
}

// ─── JWT ──────────────────────────────────────────────────────────────────────

func generateToken(user User) (string, error) {
	claims := Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func requireAuth(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			return c.Status(401).JSON(fiber.Map{"error": "Yetkisiz"})
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Geçersiz token"})
		}
		if len(roles) > 0 {
			allowed := false
			for _, r := range roles {
				if r == claims.Role {
					allowed = true
					break
				}
			}
			if !allowed {
				return c.Status(403).JSON(fiber.Map{"error": "Yetersiz yetki"})
			}
		}
		c.Locals("claims", claims)
		return c.Next()
	}
}

func getClaims(c *fiber.Ctx) *Claims {
	return c.Locals("claims").(*Claims)
}

// ─── OTP HELPERS ──────────────────────────────────────────────────────────────

func generateOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

func generateBackupCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

func ensureBackupCodes(userID string) []string {
	// Check if already exists
	var count int
	db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM backup_codes WHERE user_id=$1 AND used=false`, userID).Scan(&count)
	if count >= 3 {
		return nil
	}
	codes := make([]string, 3)
	for i := range codes {
		codes[i] = generateBackupCode()
		db.Exec(context.Background(),
			`INSERT INTO backup_codes(user_id,code) VALUES($1,$2)`, userID, codes[i])
	}
	return codes
}

// ─── EMAIL SERVICE ────────────────────────────────────────────────────────────

func sendEmail(to, subject, htmlBody string) error {
	cfg := getSMTPConfig()
	if cfg.Host == "" || cfg.User == "" {
		return fmt.Errorf("SMTP yapılandırılmamış")
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		cfg.From, to, subject, htmlBody)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.User, cfg.Pw, cfg.Host)

	if cfg.Sec == "ssl" {
		tlsConf := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.Dial("tcp", addr, tlsConf)
		if err != nil {
			return err
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer client.Close()
		if err = client.Auth(auth); err != nil {
			return err
		}
		if err = client.Mail(cfg.From); err != nil {
			return err
		}
		if err = client.Rcpt(to); err != nil {
			return err
		}
		w, _ := client.Data()
		w.Write([]byte(msg))
		w.Close()
		return client.Quit()
	}
	// STARTTLS or plain
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, []byte(msg))
}

// ─── AUDIT LOG ────────────────────────────────────────────────────────────────

func addLog(logType, icon, msg, detail, userEmail string) {
	db.Exec(context.Background(),
		`INSERT INTO audit_logs(type,icon,msg,detail,user_email) VALUES($1,$2,$3,$4,$5)`,
		logType, icon, msg, detail, userEmail)
}

// ─── AUTH HANDLERS ────────────────────────────────────────────────────────────

// POST /api/auth/send-otp
func sendOTPHandler(c *fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&body); err != nil || body.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "E-posta gerekli"})
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))

	// Verify user exists and is active
	var userID, role string
	err := db.QueryRow(context.Background(),
		`SELECT id, role FROM users WHERE email=$1 AND active=true AND role IN ('USER','CONTROLLER')`,
		email).Scan(&userID, &role)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Bu e-posta kayıtlı değil"})
	}

	code := generateOTP()
	exp := time.Now().Add(10 * time.Minute)

	// Upsert OTP
	db.Exec(context.Background(),
		`INSERT INTO otp_codes(email,code,expires_at) VALUES($1,$2,$3)
         ON CONFLICT(email) DO UPDATE SET code=$2, expires_at=$3`, email, code, exp)

	cfg := getSMTPConfig()
	smtpOK := cfg.Host != "" && cfg.User != "" && cfg.OTPEnabled

	resp := fiber.Map{"ok": true, "smtp_configured": smtpOK}
	if smtpOK {
		go sendEmail(email, "DocFlow — Giriş Kodunuz",
			fmt.Sprintf(`<b>Giriş kodunuz:</b> <span style="font-size:24px;font-weight:bold;font-family:monospace">%s</span><br><br>Bu kod 10 dakika geçerlidir.`, code))
	} else {
		// Dev mode: return code in response
		resp["dev_otp"] = code
	}
	return c.JSON(resp)
}

// POST /api/auth/verify-otp
func verifyOTPHandler(c *fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}

	var dbCode string
	var exp time.Time
	err := db.QueryRow(context.Background(),
		`SELECT code, expires_at FROM otp_codes WHERE email=$1`,
		strings.ToLower(body.Email)).Scan(&dbCode, &exp)
	if err != nil || dbCode != body.Code {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz kod"})
	}
	if time.Now().After(exp) {
		return c.Status(401).JSON(fiber.Map{"error": "Kod süresi dolmuş"})
	}

	// Delete used OTP
	db.Exec(context.Background(), `DELETE FROM otp_codes WHERE email=$1`, body.Email)

	// Load user
	var user User
	db.QueryRow(context.Background(),
		`SELECT id,email,name,surname,role,active,created_at FROM users WHERE email=$1`,
		strings.ToLower(body.Email)).Scan(
		&user.ID, &user.Email, &user.Name, &user.Surname, &user.Role, &user.Active, &user.CreatedAt)

	token, _ := generateToken(user)
	backupCodes := ensureBackupCodes(user.ID)
	return c.JSON(fiber.Map{"token": token, "user": user, "backup_codes": backupCodes})
}

// POST /api/auth/verify-backup
func verifyBackupHandler(c *fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	c.BodyParser(&body)

	var codeID, userID string
	err := db.QueryRow(context.Background(),
		`SELECT bc.id, bc.user_id FROM backup_codes bc
         JOIN users u ON u.id=bc.user_id
         WHERE u.email=$1 AND bc.code=$2 AND bc.used=false`,
		strings.ToLower(body.Email), strings.ToUpper(body.Code)).Scan(&codeID, &userID)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz yedek kod"})
	}
	db.Exec(context.Background(), `UPDATE backup_codes SET used=true WHERE id=$1`, codeID)

	var user User
	db.QueryRow(context.Background(),
		`SELECT id,email,name,surname,role,active,created_at FROM users WHERE id=$1`,
		userID).Scan(&user.ID, &user.Email, &user.Name, &user.Surname, &user.Role, &user.Active, &user.CreatedAt)

	token, _ := generateToken(user)
	return c.JSON(fiber.Map{"token": token, "user": user})
}

// POST /api/auth/admin-login
func adminLoginHandler(c *fiber.Ctx) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.BodyParser(&body)

	var user User
	var pwHash string
	err := db.QueryRow(context.Background(),
		`SELECT id,email,name,surname,role,active,created_at,password
         FROM users WHERE email=$1 AND role='ADMIN' AND active=true`,
		strings.ToLower(body.Email)).Scan(
		&user.ID, &user.Email, &user.Name, &user.Surname, &user.Role, &user.Active, &user.CreatedAt, &pwHash)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz giriş"})
	}
	if err = bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(body.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz şifre"})
	}
	token, _ := generateToken(user)
	return c.JSON(fiber.Map{"token": token, "user": user})
}

// ─── SETUP HANDLER ────────────────────────────────────────────────────────────

// GET /api/admin/setup-status
func setupStatusHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"done": getConfig("setup_done") == "true"})
}

// POST /api/admin/setup  (creates first admin)
func setupHandler(c *fiber.Ctx) error {
	var body struct {
		Email    string     `json:"email"`
		Password string     `json:"password"`
		SMTP     *SMTPConfig `json:"smtp"`
	}
	if err := c.BodyParser(&body); err != nil || body.Email == "" || body.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "E-posta ve şifre zorunlu"})
	}
	if getConfig("setup_done") == "true" {
		return c.Status(409).JSON(fiber.Map{"error": "Kurulum zaten tamamlandı"})
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	_, err := db.Exec(context.Background(),
		`INSERT INTO users(email,name,surname,role,password,active)
         VALUES($1,'Admin','',  'ADMIN',$2,true)
         ON CONFLICT(email) DO UPDATE SET role='ADMIN', password=$2`,
		strings.ToLower(body.Email), string(hash))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	setConfig("setup_done", "true")

	if body.SMTP != nil {
		setConfig("smtp_host", body.SMTP.Host)
		setConfig("smtp_port", strconv.Itoa(body.SMTP.Port))
		setConfig("smtp_sec", body.SMTP.Sec)
		setConfig("smtp_user", body.SMTP.User)
		setConfig("smtp_pw", body.SMTP.Pw)
		setConfig("smtp_from", body.SMTP.From)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// ─── USER HANDLERS ────────────────────────────────────────────────────────────

// GET /api/users
func listUsersHandler(c *fiber.Ctx) error {
	rows, err := db.Query(context.Background(),
		`SELECT id,email,name,surname,role,active,created_at FROM users
         WHERE role != 'ADMIN' ORDER BY created_at DESC`)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Email, &u.Name, &u.Surname, &u.Role, &u.Active, &u.CreatedAt)
		users = append(users, u)
	}
	return c.JSON(users)
}

// POST /api/users
func createUserHandler(c *fiber.Ctx) error {
	var body struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Surname string `json:"surname"`
		Role    string `json:"role"` // USER or CONTROLLER
	}
	if err := c.BodyParser(&body); err != nil || body.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "E-posta zorunlu"})
	}
	if body.Role != RoleUser && body.Role != RoleController {
		body.Role = RoleUser
	}
	var user User
	err := db.QueryRow(context.Background(),
		`INSERT INTO users(email,name,surname,role) VALUES($1,$2,$3,$4)
         RETURNING id,email,name,surname,role,active,created_at`,
		strings.ToLower(body.Email), body.Name, body.Surname, body.Role).Scan(
		&user.ID, &user.Email, &user.Name, &user.Surname, &user.Role, &user.Active, &user.CreatedAt)
	if err != nil {
		return c.Status(409).JSON(fiber.Map{"error": "Bu e-posta zaten kayıtlı"})
	}
	addLog("user", "👤", "Kullanıcı eklendi", body.Email, getClaims(c).Email)
	return c.Status(201).JSON(user)
}

// PUT /api/users/:id
func updateUserHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	var body struct {
		Active *bool `json:"active"`
	}
	c.BodyParser(&body)
	if body.Active != nil {
		db.Exec(context.Background(), `UPDATE users SET active=$1 WHERE id=$2`, *body.Active, id)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// DELETE /api/users/:id
func deleteUserHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	db.Exec(context.Background(), `DELETE FROM users WHERE id=$1 AND role!='ADMIN'`, id)
	return c.JSON(fiber.Map{"ok": true})
}

// GET /api/controllers  (all active CONTROLLER users — available to all authenticated roles)
func listControllersHandler(c *fiber.Ctx) error {
	type ControllerInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Surname string `json:"surname"`
	}
	rows, err := db.Query(context.Background(),
		`SELECT id, email, name, surname FROM users
         WHERE role='CONTROLLER' AND active=true ORDER BY name, email`)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()
	controllers := []ControllerInfo{}
	for rows.Next() {
		var ct ControllerInfo
		rows.Scan(&ct.ID, &ct.Email, &ct.Name, &ct.Surname)
		controllers = append(controllers, ct)
	}
	return c.JSON(controllers)
}

// ─── ASSIGNMENT HANDLERS ──────────────────────────────────────────────────────

// GET /api/assignments
func listAssignmentsHandler(c *fiber.Ctx) error {
	rows, _ := db.Query(context.Background(),
		`SELECT user_id, controller_id FROM user_controller_map`)
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var uid, cid string
		rows.Scan(&uid, &cid)
		m[uid] = cid
	}
	return c.JSON(m)
}

// PUT /api/assignments  {user_id, controller_id}
func setAssignmentHandler(c *fiber.Ctx) error {
	var body struct {
		UserID       string `json:"user_id"`
		ControllerID string `json:"controller_id"`
	}
	c.BodyParser(&body)
	if body.ControllerID == "" {
		db.Exec(context.Background(), `DELETE FROM user_controller_map WHERE user_id=$1`, body.UserID)
	} else {
		db.Exec(context.Background(),
			`INSERT INTO user_controller_map(user_id,controller_id) VALUES($1,$2)
             ON CONFLICT(user_id) DO UPDATE SET controller_id=$2`, body.UserID, body.ControllerID)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// ─── FILE HANDLERS ────────────────────────────────────────────────────────────

// POST /api/files/upload  (multipart: file + optional pdf_session_id + mod_session_id)
func uploadFileHandler(c *fiber.Ctx) error {
	claims := getClaims(c)

	fh, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Dosya gerekli"})
	}
	if !strings.HasSuffix(strings.ToLower(fh.Filename), ".pdf") {
		return c.Status(400).JSON(fiber.Map{"error": "Sadece PDF kabul edilir"})
	}

	// Save to /app/uploads
	fileID := uuid.New().String()
	ext := filepath.Ext(fh.Filename)
	storedPath := fmt.Sprintf("/app/uploads/%s%s", fileID, ext)
	if err = c.SaveFile(fh, storedPath); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Dosya kaydedilemedi"})
	}

	pdfSessID := c.FormValue("pdf_session_id")
	modSessID := c.FormValue("mod_session_id")
	expiresAt := time.Now().Add(72 * time.Hour)

	var file File
	err = db.QueryRow(context.Background(),
		`INSERT INTO files(id,original_name,stored_path,size_bytes,uploaded_by,
          pdf_session_id,mod_session_id,status,expires_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8)
         RETURNING id,original_name,size_bytes,uploaded_by,
           COALESCE(pdf_session_id,''),COALESCE(mod_session_id,''),status,expires_at,created_at`,
		fileID, fh.Filename, storedPath, fh.Size, claims.UserID,
		nullStr(pdfSessID), nullStr(modSessID), expiresAt).Scan(
		&file.ID, &file.OriginalName, &file.SizeBytes, &file.UploadedBy,
		&file.PdfSessionID, &file.ModSessionID, &file.Status, &file.ExpiresAt, &file.CreatedAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	addLog("upload", "⬆", "PDF yüklendi",
		fmt.Sprintf("%s → %s (%s)", claims.Email, fh.Filename, formatBytes(fh.Size)), claims.Email)

	return c.Status(201).JSON(file)
}

// GET /api/files  (USER=own, ADMIN=all)
func listFilesHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	var rows interface{ Next() bool }
	var err error
	if claims.Role == RoleAdmin {
		rows, err = db.Query(context.Background(),
			`SELECT id,original_name,size_bytes,uploaded_by,
              COALESCE(pdf_session_id,''),COALESCE(mod_session_id,''),
              status,expires_at,created_at FROM files ORDER BY created_at DESC`)
	} else {
		rows, err = db.Query(context.Background(),
			`SELECT id,original_name,size_bytes,uploaded_by,
              COALESCE(pdf_session_id,''),COALESCE(mod_session_id,''),
              status,expires_at,created_at FROM files WHERE uploaded_by=$1
              ORDER BY created_at DESC`, claims.UserID)
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.(*pgxpool.Rows).Close()
	files := []File{}
	for rows.(*pgxpool.Rows).Next() {
		var f File
		rows.(*pgxpool.Rows).Scan(&f.ID, &f.OriginalName, &f.SizeBytes, &f.UploadedBy,
			&f.PdfSessionID, &f.ModSessionID, &f.Status, &f.ExpiresAt, &f.CreatedAt)
		files = append(files, f)
	}
	return c.JSON(files)
}

// ─── TICKET HANDLERS ──────────────────────────────────────────────────────────

// POST /api/tickets
func createTicketHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	var body struct {
		FileID       string          `json:"file_id"`
		ControllerID string          `json:"controller_id"`
		Changes      json.RawMessage `json:"changes"`
		EditPayload  json.RawMessage `json:"edit_payload"`
		Note         string          `json:"note"`
	}
	if err := c.BodyParser(&body); err != nil || body.FileID == "" || body.ControllerID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "file_id ve controller_id zorunlu"})
	}
	if body.Changes == nil {
		body.Changes = json.RawMessage("[]")
	}

	var ticket Ticket
	err := db.QueryRow(context.Background(),
		`INSERT INTO tickets(file_id,requester_id,controller_id,status,changes,edit_payload,note)
         VALUES($1,$2,$3,'PENDING',$4,$5,$6)
         RETURNING id,file_id,requester_id,controller_id,status,changes,
           COALESCE(edit_payload::text,'{}')::jsonb,note,COALESCE(reject_reason,''),created_at`,
		body.FileID, claims.UserID, body.ControllerID, body.Changes, body.EditPayload, body.Note).Scan(
		&ticket.ID, &ticket.FileID, &ticket.RequesterID, &ticket.ControllerID,
		&ticket.Status, &ticket.Changes, &ticket.EditPayload, &ticket.Note, &ticket.RejectReason, &ticket.CreatedAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Get file info for response + email
	var fileName, pdfSess, modSess string
	var expiresAt time.Time
	db.QueryRow(context.Background(),
		`SELECT original_name, COALESCE(pdf_session_id,''), COALESCE(mod_session_id,''), expires_at
         FROM files WHERE id=$1`, body.FileID).Scan(&fileName, &pdfSess, &modSess, &expiresAt)

	ticket.FileName = fileName
	ticket.PdfSessionID = pdfSess
	ticket.ModSessionID = modSess
	ticket.ExpiresAt = expiresAt

	// Get controller email
	var ctrlEmail string
	db.QueryRow(context.Background(),
		`SELECT email FROM users WHERE id=$1`, body.ControllerID).Scan(&ctrlEmail)

	addLog("ticket", "📨", "Onay talebi gönderildi",
		fmt.Sprintf("%s → %s için %s", claims.Email, ctrlEmail, fileName), claims.Email)

	// Email notification to controller
	go func() {
		cfg := getSMTPConfig()
		if cfg.Host != "" && cfg.NotifEnabled {
			sendEmail(ctrlEmail,
				fmt.Sprintf("DocFlow — Yeni Onay Talebi: %s", fileName),
				fmt.Sprintf(`<b>%s</b> belge onayı talep etti.<br><br>
                <b>Belge:</b> %s<br>
                <b>Not:</b> %s<br><br>
                ⚠️ Bu belge <b>72 saat</b> içinde işleme alınmalıdır.<br><br>
                DocFlow sistemine giriş yaparak inceleyiniz.`, claims.Email, fileName, body.Note))
		}
	}()

	return c.Status(201).JSON(ticket)
}

// GET /api/tickets
func listTicketsHandler(c *fiber.Ctx) error {
	claims := getClaims(c)

	var query string
	var args []interface{}

	base := `SELECT t.id, t.file_id, f.original_name, t.requester_id, u1.email,
              t.controller_id, u2.email, t.status, t.changes,
              COALESCE(t.note,''), COALESCE(t.reject_reason,''),
              t.created_at, t.resolved_at, f.expires_at,
              COALESCE(f.pdf_session_id,''), COALESCE(f.mod_session_id,'')
             FROM tickets t
             JOIN files f ON f.id=t.file_id
             JOIN users u1 ON u1.id=t.requester_id
             JOIN users u2 ON u2.id=t.controller_id`

	switch claims.Role {
	case RoleUser:
		query = base + ` WHERE t.requester_id=$1 ORDER BY t.created_at DESC`
		args = []interface{}{claims.UserID}
	case RoleController:
		query = base + ` WHERE t.controller_id=$1 AND t.status='PENDING' ORDER BY t.created_at DESC`
		args = []interface{}{claims.UserID}
	default: // ADMIN
		query = base + ` ORDER BY t.created_at DESC`
	}

	rows, err := db.Query(context.Background(), query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	tickets := []Ticket{}
	for rows.Next() {
		var t Ticket
		rows.Scan(&t.ID, &t.FileID, &t.FileName, &t.RequesterID, &t.RequesterEmail,
			&t.ControllerID, &t.ControllerEmail, &t.Status, &t.Changes,
			&t.Note, &t.RejectReason, &t.CreatedAt, &t.ResolvedAt, &t.ExpiresAt,
			&t.PdfSessionID, &t.ModSessionID)
		tickets = append(tickets, t)
	}
	return c.JSON(tickets)
}

// PUT /api/tickets/:id/approve
func approveTicketHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	id := c.Params("id")
	now := time.Now()

	var reqID, fileName string
	err := db.QueryRow(context.Background(),
		`UPDATE tickets SET status='APPROVED', resolved_at=$1 WHERE id=$2
         AND (controller_id=$3 OR $4='ADMIN') RETURNING requester_id,
         (SELECT original_name FROM files WHERE id=tickets.file_id)`,
		now, id, claims.UserID, claims.Role).Scan(&reqID, &fileName)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Bilet bulunamadı"})
	}

	addLog("approve", "✅", "Onay verildi",
		fmt.Sprintf("%s → %s", claims.Email, fileName), claims.Email)

	// Email requester
	go func() {
		var reqEmail string
		db.QueryRow(context.Background(), `SELECT email FROM users WHERE id=$1`, reqID).Scan(&reqEmail)
		cfg := getSMTPConfig()
		if reqEmail != "" && cfg.Host != "" && cfg.NotifEnabled {
			sendEmail(reqEmail,
				fmt.Sprintf(`DocFlow — "%s" Onaylandı`, fileName),
				fmt.Sprintf(`Belgeniz <b>%s</b> onaylandı.<br><br>DocFlow sistemine giriş yaparak indirebilirsiniz.`, fileName))
		}
	}()

	return c.JSON(fiber.Map{"ok": true})
}

// PUT /api/tickets/:id/reject
func rejectTicketHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	id := c.Params("id")
	var body struct {
		Reason string `json:"reason"`
	}
	c.BodyParser(&body)
	if body.Reason == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Gerekçe zorunlu"})
	}

	var reqID, fileName string
	err := db.QueryRow(context.Background(),
		`UPDATE tickets SET status='REJECTED', reject_reason=$1, resolved_at=NOW()
         WHERE id=$2 AND (controller_id=$3 OR $4='ADMIN')
         RETURNING requester_id, (SELECT original_name FROM files WHERE id=tickets.file_id)`,
		body.Reason, id, claims.UserID, claims.Role).Scan(&reqID, &fileName)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Bilet bulunamadı"})
	}

	addLog("reject", "❌", "Bilet reddedildi",
		fmt.Sprintf("%s → %s: %s", claims.Email, fileName, body.Reason), claims.Email)

	go func() {
		var reqEmail string
		db.QueryRow(context.Background(), `SELECT email FROM users WHERE id=$1`, reqID).Scan(&reqEmail)
		cfg := getSMTPConfig()
		if reqEmail != "" && cfg.Host != "" && cfg.NotifEnabled {
			sendEmail(reqEmail,
				fmt.Sprintf(`DocFlow — "%s" Reddedildi`, fileName),
				fmt.Sprintf(`Belge talebiniz reddedildi.<br><br><b>Gerekçe:</b> %s`, body.Reason))
		}
	}()

	return c.JSON(fiber.Map{"ok": true})
}

// GET /api/tickets/:id/download  → proxies /apply to pdf-service
func downloadTicketHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	id := c.Params("id")

	var reqID, sessID string
	var payload json.RawMessage
	var status string
	err := db.QueryRow(context.Background(),
		`SELECT t.requester_id, COALESCE(f.mod_session_id, f.pdf_session_id,''),
              t.edit_payload, t.status
         FROM tickets t JOIN files f ON f.id=t.file_id WHERE t.id=$1`, id).Scan(
		&reqID, &sessID, &payload, &status)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Bilet bulunamadı"})
	}

	// Access control
	if claims.Role == RoleUser && reqID != claims.UserID {
		return c.Status(403).JSON(fiber.Map{"error": "Yetkisiz"})
	}
	if status != StatusApproved && claims.Role != RoleAdmin {
		return c.Status(403).JSON(fiber.Map{"error": "Belge henüz onaylanmadı"})
	}

	// Proxy to pdf-service /apply or /download
	// Forward request to Python PDF service
	client := &fiber.Client{}
	resp := client.Post(fmt.Sprintf("%s/apply/%s", pdfAPI, sessID))
	resp.Set("Content-Type", "application/json")
	resp.Body(payload)

	code, body, errs := resp.Bytes()
	if len(errs) > 0 || code != 200 {
		return c.Status(502).JSON(fiber.Map{"error": "PDF servisi yanıt vermedi"})
	}

	addLog("download", "⬇", "Dosya indirildi", "", claims.Email)
	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", `attachment; filename="edited_document.pdf"`)
	return c.Send(body)
}

// ─── ADMIN HANDLERS ───────────────────────────────────────────────────────────

// GET /api/admin/smtp
func getSMTPHandler(c *fiber.Ctx) error {
	return c.JSON(getSMTPConfig())
}

// PUT /api/admin/smtp
func saveSMTPHandler(c *fiber.Ctx) error {
	var body SMTPConfig
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}
	setConfig("smtp_host", body.Host)
	setConfig("smtp_port", strconv.Itoa(body.Port))
	setConfig("smtp_sec", body.Sec)
	setConfig("smtp_user", body.User)
	setConfig("smtp_pw", body.Pw)
	setConfig("smtp_from", body.From)
	if body.OTPEnabled {
		setConfig("smtp_otp_enabled", "true")
	} else {
		setConfig("smtp_otp_enabled", "false")
	}
	if body.NotifEnabled {
		setConfig("smtp_notif_enabled", "true")
	} else {
		setConfig("smtp_notif_enabled", "false")
	}
	addLog("email", "⚙️", "SMTP ayarları güncellendi", "", getClaims(c).Email)
	return c.JSON(fiber.Map{"ok": true})
}

// POST /api/admin/smtp/test
func testSMTPHandler(c *fiber.Ctx) error {
	claims := getClaims(c)
	if err := sendEmail(claims.Email,
		"DocFlow — Test E-postası",
		"<b>SMTP yapılandırmanız başarıyla çalışıyor!</b>"); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// GET /api/admin/logs
func listLogsHandler(c *fiber.Ctx) error {
	rows, _ := db.Query(context.Background(),
		`SELECT id,type,icon,msg,COALESCE(detail,''),COALESCE(user_email,''),created_at
         FROM audit_logs ORDER BY created_at DESC LIMIT 500`)
	defer rows.Close()
	logs := []AuditLog{}
	for rows.Next() {
		var l AuditLog
		rows.Scan(&l.ID, &l.Type, &l.Icon, &l.Msg, &l.Detail, &l.UserEmail, &l.CreatedAt)
		logs = append(logs, l)
	}
	return c.JSON(logs)
}

// GET /api/admin/disk
func diskUsageHandler(c *fiber.Ctx) error {
	var stat struct {
		Used    int64  `json:"used"`
		Total   int64  `json:"total"`
		Percent int    `json:"percent"`
		Human   string `json:"human"`
	}
	db.QueryRow(context.Background(),
		`SELECT COALESCE(SUM(size_bytes),0) FROM files WHERE status='ACTIVE'`).Scan(&stat.Used)
	stat.Total = 10 * 1024 * 1024 * 1024 // 10 GB estimate
	stat.Percent = int(float64(stat.Used) / float64(stat.Total) * 100)
	stat.Human = formatBytes(stat.Used)
	return c.JSON(stat)
}

// GET/PUT /api/admin/hints
func getHintsHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"user_email":  getConfig("hint_user_email"),
		"admin_email": getConfig("hint_admin_email"),
	})
}
func saveHintsHandler(c *fiber.Ctx) error {
	var body struct {
		UserEmail  string `json:"user_email"`
		AdminEmail string `json:"admin_email"`
	}
	c.BodyParser(&body)
	setConfig("hint_user_email", body.UserEmail)
	setConfig("hint_admin_email", body.AdminEmail)
	return c.JSON(fiber.Map{"ok": true})
}

// ─── CLEANUP JOB ──────────────────────────────────────────────────────────────
// Runs every hour:
//   72h+  ACTIVE  → ARCHIVED (zip to /archives)
//   30d+  ARCHIVED → DELETED (remove files, write deletion log)

func startCleanupJob() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for {
			runCleanup()
			<-ticker.C
		}
	}()
	log.Println("✅ Cleanup job started (hourly)")
}

func runCleanup() {
	now := time.Now()
	logFile := fmt.Sprintf("/app/logs/deletion_%s.log", now.Format("2006_01_02"))

	// 1. Archive expired ACTIVE files
	rows, err := db.Query(context.Background(),
		`SELECT id, stored_path, original_name FROM files
         WHERE status='ACTIVE' AND expires_at < NOW()`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, path, name string
			rows.Scan(&id, &path, &name)
			// Move to archives (simplified: rename)
			archivePath := strings.Replace(path, "/uploads/", "/archives/", 1)
			os.MkdirAll(filepath.Dir(archivePath), 0755)
			if err = os.Rename(path, archivePath); err == nil {
				db.Exec(context.Background(),
					`UPDATE files SET status='ARCHIVED', archived_at=NOW(),
                     stored_path=$1 WHERE id=$2`, archivePath, id)
				appendLog(logFile, fmt.Sprintf("[ARCHIVED] %s → %s", name, archivePath))
			}
		}
	}

	// 2. Delete archives older than 30 days
	rows2, err := db.Query(context.Background(),
		`SELECT id, stored_path, original_name FROM files
         WHERE status='ARCHIVED' AND archived_at < NOW() - INTERVAL '30 days'`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id, path, name string
			rows2.Scan(&id, &path, &name)
			os.Remove(path)
			db.Exec(context.Background(),
				`UPDATE files SET status='DELETED', deleted_at=NOW() WHERE id=$1`, id)
			appendLog(logFile, fmt.Sprintf("[DELETED] %s at %s", name, now.Format(time.RFC3339)))
			addLog("delete", "🗑", "Dosya kalıcı silindi", name, "system")
		}
	}
}

func appendLog(path, line string) {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(time.Now().Format(time.RFC3339) + " " + line + "\n")
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

func main() {
	// Config from environment
	jwtSecret = []byte(getEnvOrDefault("JWT_SECRET", "change-me-in-production"))
	pdfAPI = getEnvOrDefault("PDF_SERVICE_URL", "http://pdf-service:8000")

	// Database
	initDB()
	runMigrations()

	// Background jobs
	startCleanupJob()

	// Fiber app
	app := fiber.New(fiber.Config{
		BodyLimit:    200 * 1024 * 1024, // 200 MB
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})

	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))

	// ── Routes ────────────────────────────────────────────────────────────
	api := app.Group("/api")

	// Health
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "time": time.Now()})
	})

	// Setup
	api.Get("/admin/setup-status", setupStatusHandler)
	api.Post("/admin/setup", setupHandler)

	// Auth (public)
	auth := api.Group("/auth")
	auth.Post("/send-otp", sendOTPHandler)
	auth.Post("/verify-otp", verifyOTPHandler)
	auth.Post("/verify-backup", verifyBackupHandler)
	auth.Post("/admin-login", adminLoginHandler)

	// Users (ADMIN only)
	users := api.Group("/users", requireAuth(RoleAdmin))
	users.Get("/", listUsersHandler)
	users.Post("/", createUserHandler)
	users.Put("/:id", updateUserHandler)
	users.Delete("/:id", deleteUserHandler)

	// Assignments (ADMIN only)
	api.Get("/assignments", requireAuth(RoleAdmin), listAssignmentsHandler)
	api.Put("/assignments", requireAuth(RoleAdmin), setAssignmentHandler)

	// Controllers (all authenticated roles can list controllers for ticket submission)
	api.Get("/controllers", requireAuth(RoleUser, RoleController, RoleAdmin), listControllersHandler)

	// Files (USER + ADMIN)
	api.Post("/files/upload", requireAuth(RoleUser, RoleAdmin), uploadFileHandler)
	api.Get("/files", requireAuth(RoleUser, RoleAdmin), listFilesHandler)

	// Tickets
	api.Post("/tickets", requireAuth(RoleUser), createTicketHandler)
	api.Get("/tickets", requireAuth(RoleUser, RoleController, RoleAdmin), listTicketsHandler)
	api.Put("/tickets/:id/approve", requireAuth(RoleController, RoleAdmin), approveTicketHandler)
	api.Put("/tickets/:id/reject", requireAuth(RoleController, RoleAdmin), rejectTicketHandler)
	api.Get("/tickets/:id/download", requireAuth(RoleUser, RoleController, RoleAdmin), downloadTicketHandler)

	// Admin panel
	adm := api.Group("/admin", requireAuth(RoleAdmin))
	adm.Get("/smtp", getSMTPHandler)
	adm.Put("/smtp", saveSMTPHandler)
	adm.Post("/smtp/test", testSMTPHandler)
	adm.Get("/logs", listLogsHandler)
	adm.Get("/disk", diskUsageHandler)
	adm.Get("/hints", getHintsHandler)
	adm.Put("/hints", saveHintsHandler)

	port := getEnvOrDefault("PORT", "8080")
	log.Printf("🚀 DocFlow API running on :%s", port)
	log.Fatal(app.Listen(":" + port))
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
