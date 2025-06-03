function isValidUsername(username) {
  const regex = /^[a-zA-Z0-9_]{3,30}$/;
  return regex.test(username);
}

function isValidEmail(email) {
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(email);
}

function isValidPassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,100}$/;
  return regex.test(password);
}

function isValidGender(gender) {
  const validGenders = ["Male", "Female"];
  return validGenders.includes(gender);
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("inputForm");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const isRegistration = !!document.getElementById("email");

    const outputDiv = document.getElementById("output");
    outputDiv.innerHTML = "";

    // Get reCAPTCHA token
    const captchaToken = grecaptcha.getResponse();

    if (!captchaToken) {
      outputDiv.textContent = "Please complete the CAPTCHA.";
      return;
    }

    if (isRegistration) {
      const username = document.getElementById("username").value.trim();
      const email = document.getElementById("email").value.trim();
      const gender = document.querySelector('input[name="gender"]:checked')?.value;
      const password = document.getElementById("password").value;
      const confirm_password = document.getElementById("confirm_password").value;

      if (!isValidUsername(username)) {
        outputDiv.textContent = "Invalid username: use 3–30 letters, digits, or underscores.";
        return;
      }

      if (!isValidEmail(email)) {
        outputDiv.textContent = "Invalid email address.";
        return;
      }

      if (!isValidGender(gender)) {
        outputDiv.textContent = "Please select a gender (Male or Female).";
        return;
      }

      if (!isValidPassword(password)) {
        outputDiv.textContent = "Password must be 8–100 characters and include uppercase, lowercase, a number, and a special character.";
        return;
      }

      if (password !== confirm_password) {
        outputDiv.textContent = "Passwords do not match.";
        return;
      }

      // Sanitize inputs
      const cleanUsername = DOMPurify.sanitize(username);
      const cleanEmail = DOMPurify.sanitize(email);
      const cleanGender = DOMPurify.sanitize(gender);

      const userData = {
        username: cleanUsername,
        email: cleanEmail,
        gender: cleanGender,
        password,
        captchaToken,
      };

      try {
        const response = await fetch("http://localhost:3000/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(userData),
        });

        const result = await response.json();

        if (response.ok) {
          outputDiv.textContent = "Registration successful! Please log in.";
          grecaptcha.reset();
        } else {
          outputDiv.textContent = result.error || "An error occurred.";
          grecaptcha.reset();
        }
      } catch (error) {
        console.error("Error:", error);
        outputDiv.textContent = "Error submitting data. Check console.";
        grecaptcha.reset();
      }
    } else {
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value;

      if (!isValidUsername(username)) {
        outputDiv.textContent = "Invalid username format.";
        return;
      }

      if (!isValidPassword(password)) {
        outputDiv.textContent = "Invalid password format.";
        return;
      }

      try {
        const response = await fetch("http://localhost:3000/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, captchaToken }),
        });

        const result = await response.json();

        if (response.ok) {
          outputDiv.textContent = "Login successful!";
          console.log("JWT Token:", result.token);
          localStorage.setItem("jwtToken", result.token);
          grecaptcha.reset();
        } else {
          outputDiv.textContent = result.error || "Login failed.";
          grecaptcha.reset();
        }
      } catch (error) {
        console.error("Error:", error);
        outputDiv.textContent = "Error logging in. Check console.";
        grecaptcha.reset();
      }
    }
  });
});
