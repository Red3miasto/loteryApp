# lotteryApp 🎁

Gift drawing application

---

## Overview

The application was created to facilitate drawing lots in a small group, available to a single organisation.  

Over time, the code will evolve so that more people can enjoy the benefits of using an application that does not collect unnecessary data from its users – following the principle of *“less is more”*.

At this stage, the application logic assumes an administrator who adds users and sets their passwords, with the goal of minimising the amount of user data stored on the server.

---

## Security Standards Implemented

Although the current version is designed for amateur use, all common web security mechanisms have been implemented:

### 1. Password Encryption

User passwords are hashed and salted before being stored in the database (`password_hash`) and verified during login (`password_verify`).

### 2. SQL Injection Protection

All queries use prepared PDO statements (`$pdo->prepare()` and parameter binding) – an effective way to prevent SQLi attacks.

### 3. Input/Output Data Filtering

Data displayed in the UI (e.g. usernames, wish lists) is sanitized with `htmlspecialchars`, protecting against XSS vulnerabilities.

### 4. CSRF Protection

All `POST` forms include a hidden CSRF token, verified server-side to prevent CSRF attacks.

### 5. Brute Force Protection

The script limits login attempts to 5, after which further attempts are blocked for 5 minutes.

### 6. Routing Validation

Routing (page parameter handling) is restricted to a list of allowed values (`in_array(..., $allowed_pages)`), preventing access to unauthorised paths.

### 7. Correct Redirects

After login and logout, redirection is done cleanly with:
`header("Location: ...");
exit();`
This avoids unnecessary `echo` or JavaScript-based redirects.

### 8. Secure Session Handling

After login, the session ID is regenerated (`session_regenerate_id(true)`), and upon logout the session is destroyed and its cookie deleted using security flags.

### 9. Security Headers

The code sets key HTTP headers to improve browser-level protection:

- `Content-Security-Policy`  
- `X-Content-Type-Options`  
- `X-Frame-Options`  
- `Referrer-Policy`  
- `Strict-Transport-Security`

### 10. Separate Configuration

Database configuration is stored outside the public directory, minimising the risk of exposing sensitive data.

---

## Future Plans

- Add user registration functionality without compromising privacy.  
- Introduce organisation-level multi-user management.  
- Expand functionality for event management and gift distribution history.

---

## License

The project is currently in a private development stage. Future licensing details will be published once the public version is ready.
