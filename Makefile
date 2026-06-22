.PHONY: help test test-summary test-integration test-integration-docker db-test-up db-test-down test-verbose test-coverage test-race clean fmt vet lint

COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html
TEST_TIMEOUT := 120s

help:
	@echo "📋 Targets disponibles:"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test              - Ejecutar todos los tests"
	@echo "  make test-summary      - Tests con resumen corto (RECOMENDADO)"
	@echo "  make test-integration  - Solo tests de integración (requiere MySQL ya corriendo)"
	@echo "  make test-integration-docker - Integración con MySQL desechable en Docker (1 comando)"
	@echo "  make db-test-up        - Levanta el MySQL de test (Docker)"
	@echo "  make db-test-down      - Apaga y borra el MySQL de test (Docker)"
	@echo "  make test-verbose      - Tests con output detallado"
	@echo "  make test-coverage     - Tests con coverage report (HTML)"
	@echo "  make test-race         - Tests con race detector"
	@echo ""
	@echo "🧹 Code Quality:"
	@echo "  make fmt               - Formatear código (go fmt)"
	@echo "  make vet               - Análisis estático (go vet)"
	@echo "  make lint              - Lint (golangci-lint)"
	@echo ""
	@echo "🗑️  Utilities:"
	@echo "  make clean             - Limpiar archivos de test"

# Ejecutar todos los tests con resumen
test:
	@echo "🧪 Ejecutando todos los tests..."
	@go test -timeout=$(TEST_TIMEOUT) -v ./... 2>&1 | tee test-results.txt
	@echo ""
	@echo "📊 Resumen final:"
	@grep -E "^(ok|FAIL)" test-results.txt | tail -5 || true

# Tests con resumen corto (RECOMENDADO)
test-summary:
	@echo "🧪 Ejecutando tests..."
	@go test -timeout=$(TEST_TIMEOUT) -v ./test/integration 2>&1 | grep -E "^(--- PASS|--- FAIL|PASS|FAIL|ok|coverage)" | awk ' \
		BEGIN { passed=0; failed=0 } \
		/^--- PASS/ { passed++ } \
		/^--- FAIL/ { failed++ } \
		/^PASS/ { status="✅ PASS" } \
		/^FAIL/ { status="❌ FAIL" } \
		END { \
			print "\n📊 ===== RESUMEN ====="; \
			print "✅ Pasados: " passed; \
			print "❌ Fallados: " failed; \
			print "━━━━━━━━━━━━━━━━━"; \
			if (failed == 0) { print "🎉 ¡Todos los tests pasaron!" } \
			else { print "⚠️  Algunos tests fallaron" } \
		}'

# Solo tests de integración (asume un MySQL ya disponible en TEST_DB_*)
test-integration:
	@echo "🔗 Ejecutando tests de integración..."
	@go test -timeout=$(TEST_TIMEOUT) -v ./test/integration

# Integración end-to-end: levanta un MySQL desechable en Docker, corre los tests
# y lo apaga siempre (pase o falle). Un solo comando para verificar contra BD real.
test-integration-docker:
	@echo "🐳 Levantando MySQL de test (Docker)..."
	@docker compose -f docker-compose.test.yml up -d --wait
	@echo "🔗 Ejecutando tests de integración..."
	@go test -timeout=$(TEST_TIMEOUT) -v ./test/integration ; status=$$? ; \
		echo "🧹 Apagando MySQL de test..." ; \
		docker compose -f docker-compose.test.yml down -v ; \
		exit $$status

# Levanta/para el MySQL de test por separado (para iterar con `make test-integration`).
db-test-up:
	@echo "🐳 Levantando MySQL de test (Docker)..."
	@docker compose -f docker-compose.test.yml up -d --wait

db-test-down:
	@echo "🧹 Apagando MySQL de test..."
	@docker compose -f docker-compose.test.yml down -v

# Tests con output muy detallado
test-verbose:
	@echo "📝 Tests con output detallado..."
	@go test -timeout=$(TEST_TIMEOUT) -v -count=1 ./...

# Tests con coverage report
test-coverage:
	@echo "📈 Ejecutando tests con coverage..."
	@go test -timeout=$(TEST_TIMEOUT) -v -coverprofile=$(COVERAGE_FILE) ./...
	@echo ""
	@echo "📊 Coverage summary:"
	@go tool cover -func=$(COVERAGE_FILE) | tail -1
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "✅ Coverage HTML generado: $(COVERAGE_HTML)"

# Tests con race detector
test-race:
	@echo "🔍 Ejecutando tests con race detector..."
	@go test -timeout=$(TEST_TIMEOUT) -race -v ./...

# Formatear código
fmt:
	@echo "🎨 Formateando código..."
	@go fmt ./...
	@echo "✅ Código formateado"

# Go vet análisis estático
vet:
	@echo "🔎 Ejecutando go vet..."
	@go vet ./...
	@echo "✅ go vet completado"

# Lint con golangci-lint
lint:
	@echo "🧹 Ejecutando golangci-lint..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint no está instalado."; \
		echo "   Instálalo con: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Limpiar archivos de test
clean:
	@echo "🗑️  Limpiando archivos de test..."
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML) test-results.txt
	@echo "✅ Limpieza completada"
