# Password Reset Payload Example

Below is a complete example of a password reset payload in JSON format that could be used in a REST API request.

## Request Payload

```json
{
  "password_reset": {
    "email": "user@example.com",
    "new_password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "reset_token": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8",
    "client_id": "your_client_id_here",
    "client_secret": "your_client_secret_here"
  }
}
```

## Headers (if required)

```json
{
  "Content-Type": "application/json",
  "Accept": "application/json",
  "Authorization": "Bearer your_access_token_here"
}
```

## Response Payload (Success)

```json
{
  "status": "success",
  "code": 200,
  "message": "Password has been successfully reset",
  "data": {
    "user_id": "12345",
    "email": "user@example.com",
    "password_changed_at": "2023-11-15T14:30:00Z"
  }
}
```

## Response Payload (Error)

```json
{
  "status": "error",
  "code": 400,
  "message": "Password reset failed",
  "errors": [
    {
      "code": "invalid_token",
      "message": "The reset token is invalid or has expired"
    }
  ]
}
```

## Fields Explanation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's registered email address |
| new_password | string | Yes | New password (should meet complexity requirements) |
| confirm_password | string | Yes | Must match new_password |
| reset_token | string | Yes | Token received via email or SMS |
| client_id | string | Optional | For OAuth applications |
| client_secret | string | Optional | For OAuth applications |

## Security Considerations

1. Always use HTTPS for password reset endpoints
2. Enforce strong password requirements (min length, special chars, etc.)
3. Tokens should have a short expiration time (typically 1 hour)
4. Never return the actual token in response
5. Implement rate limiting to prevent brute force attacks

## Example cURL Request

```bash
curl -X POST https://api.example.com/v1/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "password_reset": {
      "email": "user@example.com",
      "new_password": "SecurePass123!",
      "confirm_password": "SecurePass123!",
      "reset_token": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"
    }
  }'
```

This markdown file provides a complete example that can be used for API documentation or implementation reference.