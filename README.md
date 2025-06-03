# Beginner-AppSec-Project
Secure Web Applcation Project 

# Secure User Registration & Login System

A simple yet secure user authentication system using Node.js, Express, and vanilla HTML/CSS/JS with client-side validation, Google reCAPTCHA, and AES-encrypted email storage.

---

##  Stack Used

- **Frontend:** HTML5, CSS3, JavaScript (vanilla)
- **Backend:** Node.js, Express.js
- **Security:** bcrypt, AES-256-CBC, JWT, Google reCAPTCHA v2
- **Other Tools:** DOMPurify (input sanitization), Express Rate Limit (brute-force protection)

---

##  Features

- User registration with:
  - Input validation (client & server)
  - Password strength enforcement
  - Google reCAPTCHA verification
  - AES-encrypted email storage
- Secure login with:
  - Rate limiting (max 5 attempts/15 mins)
  - JWT-based authentication
- Protected routes with token-based access
- Input sanitization using DOMPurify (against XSS)
- In-memory user storage (for demonstration purposes)

---

##  Setup Instruction

### 1. Install dependencies
npm install

### 2. Environment variables
AES_KEY=your_64_char_hex_key
AES_IV=your_32_char_hex_iv
RECAPTCHA_SECRET_KEY=your_google_recaptcha_secret
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=1h

### 3. Run the server
node server.js


### 4. **Security Measures**
- Implement **input validation** and **output sanitization** to prevent common attacks like **SQL injection** and **XSS**.
- Use **secure HTTP headers** (e.g., Content Security Policy, X-Frame-Options).
- Encrypt sensitive data with **AES** or other algorithms, ensuring that you never store plaintext sensitive information in the database.
- Enable **HTTPS** using SSL/TLS certificates for all communications.

### 5. **Version Control Best Practices**
- Use meaningful commit messages.
- Commit often with small changes.
- Use `.gitignore` to prevent sensitive or unnecessary files (e.g., `node_modules/`) from being tracked.

This setup will ensure proper version control and a well-documented, secure, and maintainable deployment process for your application.

