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

##  Setup Instructions

### 1.clone the reposity
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

### 2. Install dependencies
npm install

### 3. Environment variables
AES_KEY=your_64_char_hex_key
AES_IV=your_32_char_hex_iv
RECAPTCHA_SECRET_KEY=your_google_recaptcha_secret
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=1h

### 4. Run the server
node server.js
