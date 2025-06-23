```markdown
# API Endpoint Reference Guide

## Table of Contents
- [Payload Examples](#payload-examples)
  - [Authentication](#authentication)
  - [User Management](#user-management)
  - [E-Commerce](#e-commerce)
  - [Social Media](#social-media-1)
  - [Payment Processing](#payment-processing)
  - [File Upload](#file-upload)
- [Service Endpoints](#service-endpoints)
  - [Authentication & User Management](#authentication--user-management)
  - [Social Media](#social-media)
  - [E-Commerce](#e-commerce-1)
  - [Payment Gateways](#payment-gateways)
  - [Cloud Storage](#cloud-storage)
  - [Mapping & Geolocation](#mapping--geolocation)
  - [Communication](#communication)
  - [Financial Data](#financial-data)
  - [Government & Public Data](#government--public-data)

---

# Payload Examples

## Authentication

### Login Request
```json
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "securePassword123!",
  "remember_me": true
}
```

### Login Response
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "usr_12345",
    "name": "John Doe",
    "email": "user@example.com",
    "role": "customer"
  },
  "expires_in": 3600
}
```

## User Management

### Create User
```json
POST /api/v1/users
{
  "name": "Alice Smith",
  "email": "alice@example.com",
  "password": "strongPassword456!",
  "role": "editor",
  "profile": {
    "bio": "Software developer and open source contributor",
    "avatar_url": "https://example.com/avatars/default.jpg"
  }
}
```

### Update User
```json
PATCH /api/v1/users/usr_12345
{
  "name": "John Doe Jr.",
  "profile": {
    "bio": "Updated bio information",
    "website": "https://johndoe.dev"
  }
}
```

## E-Commerce

### Create Product
```json
POST /api/v1/products
{
  "name": "Wireless Bluetooth Headphones",
  "description": "Premium noise-cancelling headphones with 30hr battery life",
  "price": 199.99,
  "currency": "USD",
  "stock": 150,
  "categories": ["electronics", "audio"],
  "specs": {
    "color": "black",
    "weight": "250g",
    "battery_life": "30 hours"
  }
}
```

### Place Order
```json
POST /api/v1/orders
{
  "user_id": "usr_12345",
  "items": [
    {
      "product_id": "prod_67890",
      "quantity": 2,
      "price": 199.99
    }
  ],
  "shipping_address": {
    "street": "123 Main St",
    "city": "New York",
    "state": "NY",
    "zip_code": "10001",
    "country": "USA"
  },
  "payment_method": "credit_card"
}
```

## Social Media

### Create Post
```json
POST /api/v1/posts
{
  "user_id": "usr_12345",
  "content": "Just launched my new website! Check it out at https://example.com",
  "tags": ["announcement", "website"],
  "visibility": "public",
  "location": {
    "lat": 40.7128,
    "lng": -74.0060,
    "name": "New York, NY"
  }
}
```

### Add Comment
```json
POST /api/v1/posts/post_12345/comments
{
  "user_id": "usr_67890",
  "content": "Congratulations! The site looks amazing.",
  "parent_comment_id": null
}
```

## Payment Processing

### Process Payment
```json
POST /api/v1/payments
{
  "amount": 399.98,
  "currency": "USD",
  "source": "tok_visa1234",
  "description": "Order #12345",
  "metadata": {
    "order_id": "ord_12345",
    "customer_id": "usr_12345"
  }
}
```

### Payment Response
```json
{
  "id": "pay_12345",
  "amount": 399.98,
  "currency": "USD",
  "status": "succeeded",
  "payment_method": "visa",
  "last4": "4242",
  "receipt_url": "https://payments.example.com/receipts/pay_12345",
  "created_at": "2023-04-15T12:34:56Z"
}
```

## File Upload

### Upload File Request
```json
POST /api/v1/uploads
Content-Type: multipart/form-data

{
  "file": "(binary file data)",
  "metadata": {
    "name": "profile_picture.jpg",
    "type": "image/jpeg",
    "description": "User profile picture",
    "tags": ["profile", "image"]
  }
}
```

### Upload Response
```json
{
  "id": "file_12345",
  "url": "https://storage.example.com/files/profile_picture.jpg",
  "size": 245678,
  "mime_type": "image/jpeg",
  "uploaded_at": "2023-04-15T12:35:10Z"
}
```

---

# Service Endpoints

## Authentication & User Management

### Auth0
```
POST /oauth/token - Get access token
GET /userinfo - Get user profile
POST /dbconnections/signup - User registration
POST /dbconnections/change_password - Password change
```

### Firebase Authentication
```
POST /v1/accounts:signUpWithPassword - Email/password signup
POST /v1/accounts:signInWithPassword - Email/password login
POST /v1/accounts:sendOobCode - Send password reset email
POST /v1/accounts:update - Update user profile
```

## Social Media

### Twitter API v2
```
GET /2/users/me - Get authenticated user profile
GET /2/users/:id/tweets - Get user tweets
POST /2/tweets - Create tweet
DELETE /2/tweets/:id - Delete tweet
```

### Instagram Graph API
```
GET /me - Get user profile
GET /me/media - Get user media
GET /{media-id} - Get media details
POST /me/media - Create media container
```

### Reddit API
```
POST /api/v1/access_token - Get OAuth token
GET /api/v1/me - Get user profile
POST /api/submit - Create post
GET /r/{subreddit}/hot - Get hot posts
```

## E-Commerce

### Shopify Admin API
```
GET /admin/api/2023-01/products.json - List products
POST /admin/api/2023-01/products.json - Create product
GET /admin/api/2023-01/orders.json - List orders
POST /admin/api/2023-01/orders.json - Create order
```

### WooCommerce REST API
```
GET /wp-json/wc/v3/products - List products
POST /wp-json/wc/v3/products - Create product
GET /wp-json/wc/v3/orders - List orders
PUT /wp-json/wc/v3/orders/:id - Update order
```

## Payment Gateways

### Stripe API
```
POST /v1/payment_intents - Create payment intent
POST /v1/charges - Create charge
GET /v1/customers/:id - Retrieve customer
POST /v1/refunds - Create refund
```

### PayPal REST API
```
POST /v1/oauth2/token - Get access token
POST /v1/payments/payouts - Create payout
POST /v2/checkout/orders - Create order
GET /v2/payments/captures/:id - Get capture details
```

## Cloud Storage

### AWS S3 API
```
PUT /{bucket}/{key} - Upload object
GET /{bucket}/{key} - Download object
DELETE /{bucket}/{key} - Delete object
GET /{bucket}?list-type=2 - List objects
```

### Google Drive API
```
GET /drive/v3/files - List files
POST /upload/drive/v3/files - Upload file
PATCH /drive/v3/files/{fileId} - Update file metadata
DELETE /drive/v3/files/{fileId} - Delete file
```

## Mapping & Geolocation

### Google Maps Platform
```
GET /maps/api/geocode/json - Geocoding
GET /maps/api/directions/json - Get directions
GET /maps/api/place/nearbysearch/json - Nearby places
GET /maps/api/staticmap - Static map image
```

### Mapbox API
```
GET /geocoding/v5/{endpoint}/{query}.json - Forward/reverse geocoding
GET /directions/v5/{profile}/{coordinates} - Get directions
GET /styles/v1/{username}/{style_id}/static/{overlay}/{lon},{lat},{zoom}/{dimensions} - Static map
```

## Communication

### Twilio API
```
POST /2010-04-01/Accounts/{AccountSid}/Messages.json - Send SMS
POST /2010-04-01/Accounts/{AccountSid}/Calls.json - Make phone call
GET /2010-04-01/Accounts/{AccountSid}/Messages/{MessageSid}.json - Get message
```

### SendGrid API
```
POST /v3/mail/send - Send email
GET /v3/suppression/bounces - Get bounce list
DELETE /v3/suppression/bounces/{email} - Delete bounce
```

## Financial Data

### Plaid API
```
POST /link/token/create - Create link token
POST /item/public_token/exchange - Exchange public token
POST /accounts/balance/get - Get account balances
POST /transactions/get - Get transactions
```

### Alpha Vantage Stock API
```
GET /query?function=TIME_SERIES_INTRADAY&symbol=IBM - Stock time series
GET /query?function=CURRENCY_EXCHANGE_RATE - Currency exchange rate
GET /query?function=GLOBAL_QUOTE - Stock quote
```

## Government & Public Data

### NASA APIs
```
GET /planetary/apod - Astronomy Picture of the Day
GET /neo/rest/v1/feed - Near Earth Objects
GET /mars-photos/api/v1/rovers/curiosity/photos - Mars rover photos
```

### Data.gov APIs
```
GET /api/views/{dataset-id}/rows.json - Various public datasets
GET /api/action/datastore_search - CKAN data store search
```

---

## Notes
1. All endpoints may require authentication (API keys, OAuth tokens, etc.)
2. Base URLs are service-specific (e.g., `https://api.stripe.com` for Stripe)
3. Always check official documentation for the most current API versions
4. Rate limits and usage restrictions typically apply
5. For production use, implement proper error handling and security measures
```
