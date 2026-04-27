package mysql

import (
	"context"
	"database/sql"
)

type contextKeyTx struct{}

var ctxKeyTx = contextKeyTx{}

// TxFromContext devuelve la *sql.Tx asociada al contexto si existe (dentro de WithTransaction).
func TxFromContext(ctx context.Context) *sql.Tx {
	if tx, ok := ctx.Value(ctxKeyTx).(*sql.Tx); ok {
		return tx
	}
	return nil
}

// execContexter permite usar *sql.DB o *sql.Tx en operaciones ExecContext.
type execContexter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// execContextFrom devuelve la tx del contexto si existe, sino db. Para usar en repos dentro de WithTransaction.
func execContextFrom(ctx context.Context, db *sql.DB) execContexter {
	if tx := TxFromContext(ctx); tx != nil {
		return tx
	}
	return db
}

// dbExecutor extends execContexter with query capabilities for SELECT ... FOR UPDATE inside transactions.
type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func dbFrom(ctx context.Context, db *sql.DB) dbExecutor {
	if tx := TxFromContext(ctx); tx != nil {
		return tx
	}
	return db
}

// TransactionRunner ejecuta una función dentro de una transacción.
type TransactionRunner struct {
	db *sql.DB
}

// NewTransactionRunner crea un runner que usa la DB dada.
func NewTransactionRunner(db *sql.DB) *TransactionRunner {
	return &TransactionRunner{db: db}
}

// WithTransaction abre una transacción, la guarda en ctx y ejecuta fn(ctx).
// Si fn retorna error se hace rollback; si no, commit.
func (r *TransactionRunner) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txCtx := context.WithValue(ctx, ctxKeyTx, tx)
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
