import assert from "node:assert/strict";
import {
  validateEmail,
  validateLoginPassword,
  validateRegisterPassword,
  validateConfirmPassword,
} from "../src/features/auth/validation.ts";

console.log("=== RUNNING AUTH VALIDATION UNIT TESTS ===");

// 1. Email validation
console.log("Testing validateEmail...");
assert.equal(validateEmail(""), "Please enter your email address.");
assert.equal(validateEmail("   "), "Please enter your email address.");
assert.equal(validateEmail("test"), "Please enter a valid email address.");
assert.equal(validateEmail("test@"), "Please enter a valid email address.");
assert.equal(validateEmail("@test.com"), "Please enter a valid email address.");
assert.equal(validateEmail("test@domain"), "Please enter a valid email address.");
assert.equal(validateEmail("test..user@example.com"), "Please enter a valid email address.");
assert.equal(validateEmail("analyst@domain.gov"), null);
assert.equal(validateEmail("user@example.com"), null);
assert.equal(validateEmail("user.name+tag@sub.domain.co.uk"), null);
console.log("✓ Email validation tests passed");

// 2. Login password validation
console.log("Testing validateLoginPassword...");
assert.equal(validateLoginPassword(""), "Please enter a password.");
assert.equal(validateLoginPassword("any-password"), null);
console.log("✓ Login password validation tests passed");

// 3. Register password validation
console.log("Testing validateRegisterPassword...");
assert.equal(validateRegisterPassword(""), "Please enter a password.");
assert.equal(validateRegisterPassword("short1!"), "Password must be at least 8 characters.");
// No number
assert.equal(
  validateRegisterPassword("PasswordWithoutNumber!"),
  "Use at least 8 characters, including a number and an uppercase letter or special character."
);
// No uppercase or special
assert.equal(
  validateRegisterPassword("password12345"),
  "Use at least 8 characters, including a number and an uppercase letter or special character."
);
// Valid: number + uppercase
assert.equal(validateRegisterPassword("Password123"), null);
// Valid: number + special
assert.equal(validateRegisterPassword("password123!"), null);
// Valid: number + uppercase + special
assert.equal(validateRegisterPassword("StrongPassword123!"), null);
console.log("✓ Register password validation tests passed");

// 4. Confirm password validation
console.log("Testing validateConfirmPassword...");
assert.equal(validateConfirmPassword("Password123!", ""), "Please confirm your password.");
assert.equal(validateConfirmPassword("Password123!", "Mismatch123!"), "Passwords do not match.");
assert.equal(validateConfirmPassword("Password123!", "Password123!"), null);
console.log("✓ Confirm password validation tests passed");

console.log("\nALL AUTH VALIDATION UNIT TESTS PASSED SUCCESSFULLY!");
