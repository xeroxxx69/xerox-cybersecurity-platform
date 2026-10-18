/**
 * Client-side authentication validation rules.
 * Enforces strict email syntax checks and clear, user-friendly field-level error messages.
 */

export function validateEmail(email: string): string | null {
  const trimmed = (email || "").trim();
  if (!trimmed) {
    return "Please enter your email address.";
  }

  // Reject consecutive dots
  if (trimmed.includes("..")) {
    return "Please enter a valid email address.";
  }

  // Must contain exactly one '@'
  const atIndex = trimmed.indexOf("@");
  if (atIndex <= 0 || atIndex !== trimmed.lastIndexOf("@") || atIndex === trimmed.length - 1) {
    return "Please enter a valid email address.";
  }

  const localPart = trimmed.slice(0, atIndex);
  const domainPart = trimmed.slice(atIndex + 1);

  if (!localPart || !domainPart) {
    return "Please enter a valid email address.";
  }

  // Domain must contain at least one dot
  const domainParts = domainPart.split(".");
  if (domainParts.length < 2) {
    return "Please enter a valid email address.";
  }

  // Check each domain segment
  for (const part of domainParts) {
    if (!part || part.startsWith("-") || part.endsWith("-")) {
      return "Please enter a valid email address.";
    }
  }

  // Top-level domain must be at least 2 alphabetic characters
  const tld = domainParts[domainParts.length - 1];
  if (tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) {
    return "Please enter a valid email address.";
  }

  // Full email structure validation
  const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!regex.test(trimmed)) {
    return "Please enter a valid email address.";
  }

  return null;
}

export function validateLoginPassword(password: string): string | null {
  if (!password) {
    return "Please enter a password.";
  }
  return null;
}

export function validateRegisterPassword(password: string): string | null {
  if (!password) {
    return "Please enter a password.";
  }

  if (password.length < 8) {
    return "Password must be at least 8 characters.";
  }

  // Requirements: at least 1 number AND (at least 1 uppercase letter OR special character)
  const hasNumber = /\d/.test(password);
  const hasUpperOrSpecial = /[A-Z]/.test(password) || /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);

  if (!hasNumber || !hasUpperOrSpecial) {
    return "Use at least 8 characters, including a number and an uppercase letter or special character.";
  }

  return null;
}

export function validateConfirmPassword(password: string, confirmPassword: string): string | null {
  if (!confirmPassword) {
    return "Please confirm your password.";
  }
  if (password !== confirmPassword) {
    return "Passwords do not match.";
  }
  return null;
}
