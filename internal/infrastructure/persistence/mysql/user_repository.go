package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, password, name, phone, verified, token_version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Convert empty strings to NULL for optional fields
	var email sql.NullString
	if user.Email != "" {
		email = sql.NullString{String: user.Email, Valid: true}
	}

	var phone sql.NullString
	if user.Phone != "" {
		phone = sql.NullString{String: user.Phone, Valid: true}
	}

	_, err := execContextFrom(ctx, r.db).ExecContext(ctx, query,
		user.ID, email, user.Password, user.Name, phone,
		user.Verified, user.TokenVersion, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error creating user", 500, err)
	}

	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, token_version, created_at, updated_at, deleted_at
		FROM users WHERE id = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime
	var email sql.NullString
	var phone sql.NullString

	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, id).Scan(
		&user.ID, &email, &user.Password, &user.Name, &phone,
		&user.Verified, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, appErrors.NewNotFoundError("User")
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if email.Valid {
		user.Email = email.String
	}

	if phone.Valid {
		user.Phone = phone.String
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, token_version, created_at, updated_at, deleted_at
		FROM users WHERE email = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime
	var emailNull sql.NullString
	var phone sql.NullString

	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, email).Scan(
		&user.ID, &emailNull, &user.Password, &user.Name, &phone,
		&user.Verified, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if emailNull.Valid {
		user.Email = emailNull.String
	}

	if phone.Valid {
		user.Phone = phone.String
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) GetByPhone(ctx context.Context, phoneQuery string) (*domain.User, error) {
	query := `
		SELECT id, email, password, name, phone, verified, token_version, created_at, updated_at, deleted_at
		FROM users WHERE phone = ? AND deleted_at IS NULL
	`

	var user domain.User
	var deletedAt sql.NullTime
	var email sql.NullString
	var phone sql.NullString

	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, phoneQuery).Scan(
		&user.ID, &email, &user.Password, &user.Name, &phone,
		&user.Verified, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching user", 500, err)
	}

	if email.Valid {
		user.Email = email.String
	}

	if phone.Valid {
		user.Phone = phone.String
	}

	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users 
		SET email = ?, name = ?, phone = ?, verified = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	// Convert empty strings to NULL for optional fields
	var email sql.NullString
	if user.Email != "" {
		email = sql.NullString{String: user.Email, Valid: true}
	}

	var phone sql.NullString
	if user.Phone != "" {
		phone = sql.NullString{String: user.Phone, Valid: true}
	}

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query,
		email, user.Name, phone, user.Verified, time.Now(), user.ID,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error updating user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error checking changes", 500, err)
	}

	if rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

// BumpTokenVersion increments token_version by 1, revoking every JWT
// (access and refresh) issued before this point. Used by /auth/refresh so
// rotation is real: the refresh token just consumed cannot be replayed.
func (r *UserRepository) BumpTokenVersion(ctx context.Context, userID string) (int, error) {
	// LAST_INSERT_ID(expr) fija y devuelve, por conexión, el valor exacto que
	// este UPDATE escribió. Así dos refresh concurrentes obtienen cada uno su
	// versión real (no la leída antes en memoria), evitando firmar un token con
	// una versión ya superada en BD (que quedaría inválido al instante).
	query := `
		UPDATE users
		SET token_version = LAST_INSERT_ID(token_version + 1), updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error rotando refresh token", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error verificando rotación", 500, err)
	}
	if rows == 0 {
		return 0, appErrors.NewNotFoundError("Usuario")
	}

	newVersion, err := result.LastInsertId()
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error verificando rotación", 500, err)
	}

	return int(newVersion), nil
}

// UpdatePasswordAndBumpTokenVersion swaps the password hash and increments
// token_version atomically. The version bump revokes every JWT issued before
// this point; combined with auth middleware, it forces re-login.
func (r *UserRepository) UpdatePasswordAndBumpTokenVersion(ctx context.Context, userID, passwordHash string) (int, error) {
	// Ver BumpTokenVersion: LAST_INSERT_ID(expr) devuelve el valor escrito para
	// firmar el token nuevo con la versión real resultante en BD.
	query := `
		UPDATE users
		SET password = ?, token_version = LAST_INSERT_ID(token_version + 1), updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, passwordHash, time.Now(), userID)
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error actualizando contraseña", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error verificando cambios", 500, err)
	}
	if rows == 0 {
		return 0, appErrors.NewNotFoundError("Usuario")
	}

	newVersion, err := result.LastInsertId()
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error verificando cambios", 500, err)
	}

	return int(newVersion), nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE users SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting user", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting user", 500, err)
	}
	if rows == 0 {
		return appErrors.NewNotFoundError("User")
	}

	return nil
}

// ListWithSummary lists a paginated, optionally filtered slice of users plus
// global counts (total, active, inactive). q is matched against name, email
// and phone with LIKE so the admin UI can search by any of them.
func (r *UserRepository) ListWithSummary(ctx context.Context, limit, offset int, q string) ([]*domain.User, int, int, int, error) {
	q = strings.TrimSpace(q)
	args := []any{}
	whereFiltered := "WHERE deleted_at IS NULL"
	if q != "" {
		// Escapar comodines LIKE: sin esto, un q con % o _ se interpreta como
		// patrón (q="%" listaría todo y patrones pesados degradan la consulta).
		// La parametrización ya evita inyección SQL; esto evita inyección de
		// comodines.
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
		like := "%" + escaped + "%"
		whereFiltered += " AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)"
		args = append(args, like, like, like)
	}

	listQuery := fmt.Sprintf(`
		SELECT id, email, password, name, phone, verified, token_version, created_at, updated_at, deleted_at
		FROM users
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`, whereFiltered)
	listArgs := append(append([]any{}, args...), limit, offset)

	rows, err := dbFrom(ctx, r.db).QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, 0, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing users", 500, err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		var user domain.User
		var deletedAt sql.NullTime
		var email sql.NullString
		var phone sql.NullString
		if err := rows.Scan(
			&user.ID, &email, &user.Password, &user.Name, &phone,
			&user.Verified, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt, &deletedAt,
		); err != nil {
			return nil, 0, 0, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error scanning user", 500, err)
		}
		if email.Valid {
			user.Email = email.String
		}
		if phone.Valid {
			user.Phone = phone.String
		}
		if deletedAt.Valid {
			user.DeletedAt = &deletedAt.Time
		}
		users = append(users, &user)
	}
	// rows.Err() captura errores de iteración (p. ej. conexión cortada a mitad
	// del result set), que de otro modo se confundirían con "no hay más filas".
	if err := rows.Err(); err != nil {
		return nil, 0, 0, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing users", 500, err)
	}

	// Totals are computed without the q filter and without LIMIT/OFFSET so the
	// summary reflects the global state, not the page.
	// COALESCE: con la tabla vacía SUM devuelve NULL y el Scan a int fallaría.
	var total, active, inactive int
	if err := dbFrom(ctx, r.db).QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN verified = TRUE THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN verified = FALSE THEN 1 ELSE 0 END), 0)
		FROM users WHERE deleted_at IS NULL`).Scan(&total, &active, &inactive); err != nil {
		return nil, 0, 0, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error computing user summary", 500, err)
	}

	return users, total, active, inactive, nil
}

