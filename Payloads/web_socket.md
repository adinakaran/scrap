```markdown
# WebSocket Payload Example

This document demonstrates a typical WebSocket payload structure for both client-to-server and server-to-client communication.

## Basic Text Payload

```json
{
  "type": "chat_message",
  "sender": "user123",
  "content": "Hello, world!",
  "timestamp": 1620000000000
}
```

## Binary Payload Example

For binary data, WebSockets typically use:

```
<binary data> (e.g., image, audio, or compressed data)
```

## Common Payload Structures

### 1. Authentication Payload

```json
{
  "action": "authenticate",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 2. Subscription Payload

```json
{
  "action": "subscribe",
  "channel": "market_data",
  "symbol": "BTC-USD"
}
```

### 3. Real-time Update

```json
{
  "event": "price_update",
  "symbol": "BTC-USD",
  "price": 50000.42,
  "change": 1.23
}
```

### 4. Error Response

```json
{
  "status": "error",
  "code": 4001,
  "message": "Invalid authentication token"
}
```

## WebSocket Frame Structure

| Field       | Description                              |
|-------------|------------------------------------------|
| FIN         | 1 bit (indicates if this is the final fragment) |
| RSV1-3      | 1 bit each (reserved)                   |
| Opcode      | 4 bits (text, binary, close, ping, pong)|
| Mask        | 1 bit (indicates if payload is masked)  |
| Payload Len | 7/7+16/7+64 bits (payload length)       |
| Masking Key | 0 or 4 bytes (if Mask=1)                |
| Payload Data | n bytes (actual data)                  |

## Example Sequence

1. **Client connects** to `wss://example.com/socket`
2. **Server responds** with HTTP 101 Switching Protocols
3. **Client sends** authentication:
   ```json
   {"action":"auth","token":"abc123"}
   ```
4. **Server confirms**:
   ```json
   {"status":"authenticated"}
   ```
5. **Client subscribes**:
   ```json
   {"action":"subscribe","channel":"notifications"}
   ```
6. **Server pushes** data:
   ```json
   {"channel":"notifications","data":"New message received"}
   ```

## Best Practices

- Use JSON for structured data
- Include message types/actions for routing
- Implement ping/pong for connection health
- Handle connection drops gracefully
- Compress large payloads when appropriate
```
