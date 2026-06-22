# 🧪 Testing Notes

This file documents how to run the test suite and notable cases.

## Integration tests (MySQL)

The tests in `test/integration/` need a real MySQL. The fastest path is a
disposable container — one command, brought up and torn down automatically:

```bash
make test-integration-docker
```

Or manage the database yourself (handy for iterating):

```bash
make db-test-up         # start a disposable MySQL (Docker)
make test-integration   # run the suite against it, repeatable
make db-test-down       # stop + wipe
```

Connection settings live in `test/integration/setup_test.go` and match
`docker-compose.test.yml` (root/`password` @ `127.0.0.1:3306`, DB
`genericbackendtest`). Override them with `TEST_DB_*` env vars or a `.env.test`
(copy `.env.test.example`). The DB name **must contain "test"** — a safety guard
checked before the suite drops it. Unit tests need no DB and run with `go test`.

## Login by phone

- The authentication flow supports logging in using either `email` + `password` or `phone` + `password`.
- To exercise login-by-phone in integration tests we insert a test user with a phone number and then POST to `/api/v1/auth/login` with the JSON payload:

```json
{
  "phone": "+573001234567",
  "password": "password123"
}
```

- The endpoint returns the same envelope as login-by-email: `data.token`, `data.refresh_token`, `data.user_id`, `data.email`.
- The integration test case is `TestAuthLogin` -> subtest `Login by phone` (see `test/integration/auth_test.go`).

Run the summarized test command:

```bash
make test-summary
```
