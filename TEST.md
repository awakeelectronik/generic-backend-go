# 🧪 Testing Notes

This file documents how to run the test suite and notable cases.

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
