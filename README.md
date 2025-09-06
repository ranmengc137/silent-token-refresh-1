# Silent Token Refresh with Spring Security

This project demonstrates a complete **access/refresh token authentication flow** using Spring Boot 3, Spring Security, Spring Cloud Gateway, and JSON Web Tokens (JWT).
It supports both **client-side silent refresh** and **server-side refresh at the gateway**, with **method-level security enforcement** in the resource service.

---

## Architecture

The system is composed of three services:

- **Gateway (8080)**
  - Routes requests to the appropriate service.
  - Validates access tokens.
  - Returns **511** if the access token is expired.
  - Optionally performs **server-side refresh** using the refresh token.
  - Serves a demo frontend UI.

- **Auth Service (8081)**
  - `POST /auth/login` – issues a short-lived access token (20s) and a longer-lived refresh token (5m).
  - `GET /auth/refresh` – refreshes the access token using the refresh token.
  - Tokens include a **roles** claim (`ROLE_USER`).

- **Resource Service (8082)**
  - Exposes a protected endpoint `GET /api/data`.
  - Secured with **Spring Security** and a custom JWT filter.
  - Method-level protection with `@PreAuthorize("hasRole('USER')")`.

---

## How to Run

### Requirements
- Java 17+
- Maven (wrapper included)

### Steps
Open three terminals in the root directory:

```bash
# Auth Service
./mvnw -pl auth-service -am spring-boot:run
```

```bash
# Resource Service
./mvnw -pl resource-service -am spring-boot:run
```

```bash
# Gateway
./mvnw -pl gateway -am spring-boot:run
```

Then open **http://localhost:8080** in your browser.

---

## Demo Flow

1. **Login**
   - Use any username/password.
   - Auth service returns access and refresh tokens plus expiration times.
   - Tokens are stored in `sessionStorage`.

2. **Call Protected Endpoint**
   - **Client-side refresh**: Axios interceptors catch 511, refresh with the refresh token, and replay the original request.
   - **Server-side refresh**: Gateway refreshes automatically when provided with both access and refresh tokens, returning a new token in the `X-New-Token` header.

3. **Proactive Refresh**
   - A timer runs in the client.
   - If the access token is about to expire, it automatically refreshes in the background.

4. **Spring Security Check**
   - Resource service requires `ROLE_USER`.
   - Invalid or role-less tokens are rejected with **401 Unauthorized**.

---

## Key Files

### Gateway
- `gateway/src/main/java/com/example/gateway/JwtGatewayFilterFactory.java` – validates access tokens, returns 511, supports optional server-side refresh.
- `gateway/src/main/resources/static/index.html` – frontend demo UI with Axios interceptors and proactive timer.

### Auth Service
- `auth-service/src/main/java/com/example/auth/AuthController.java` – login and refresh endpoints, issues tokens with roles.
- `auth-service/src/main/java/com/example/common/JwtUtil.java` – JWT creation and parsing utilities.

### Resource Service
- `resource-service/src/main/java/com/example/resource/SecurityConfig.java` – Spring Security configuration (stateless, JWT filter).
- `resource-service/src/main/java/com/example/resource/JwtAuthFilter.java` – validates access tokens, sets roles in `SecurityContext`.
- `resource-service/src/main/java/com/example/resource/DataController.java` – protected endpoint with `@PreAuthorize("hasRole('USER')")`.

---
