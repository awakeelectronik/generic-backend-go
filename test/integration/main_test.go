package integration

import (
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func TestMain(m *testing.M) {
	// Estamos en test/integration, subimos un nivel hasta la raíz
	if err := godotenv.Load("../../.env.test"); err != nil {
		println("NO se pudo cargar ../../.env.test:", err.Error())
	} else {
		println("../.env.test CARGADO OK")
	}

	os.Exit(m.Run())
}
