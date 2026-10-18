import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, Lock, Mail, ArrowRight, AlertTriangle } from "lucide-react";
import {
  useAuth,
  validateEmail,
  validateRegisterPassword,
  validateConfirmPassword,
} from "@/features/auth";
import { Input, Button, Card } from "@/components/ui";

export const RegisterPage: React.FC = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{
    email?: string;
    password?: string;
    confirmPassword?: string;
  }>({});
  const [serverError, setServerError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    if (fieldErrors.email) {
      setFieldErrors((prev) => ({ ...prev, email: undefined }));
    }
    if (serverError) {
      setServerError(null);
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (fieldErrors.password) {
      setFieldErrors((prev) => ({ ...prev, password: undefined }));
    }
    if (fieldErrors.confirmPassword && confirmPassword === e.target.value) {
      setFieldErrors((prev) => ({ ...prev, confirmPassword: undefined }));
    }
    if (serverError) {
      setServerError(null);
    }
  };

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setConfirmPassword(e.target.value);
    if (fieldErrors.confirmPassword) {
      setFieldErrors((prev) => ({ ...prev, confirmPassword: undefined }));
    }
    if (serverError) {
      setServerError(null);
    }
  };

  const handleRegister = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setServerError(null);

    const emailError = validateEmail(email);
    const passwordError = validateRegisterPassword(password);
    const confirmPasswordError = validateConfirmPassword(password, confirmPassword);

    if (emailError || passwordError || confirmPasswordError) {
      setFieldErrors({
        email: emailError || undefined,
        password: passwordError || undefined,
        confirmPassword: confirmPasswordError || undefined,
      });
      return;
    }

    setFieldErrors({});
    setLoading(true);

    try {
      await register(email.trim(), password);
      navigate("/dashboard", { replace: true });
    } catch (err: any) {
      const msg = err.message || "Registration failed. Please try again.";
      if (
        msg.toLowerCase().includes("already registered") ||
        msg.toLowerCase().includes("already exists")
      ) {
        const duplicateMsg = "This email is already registered. Please sign in instead.";
        setFieldErrors((prev) => ({ ...prev, email: duplicateMsg }));
        setServerError(duplicateMsg);
      } else {
        setServerError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[75vh] flex items-center justify-center px-4">
      <Card className="w-full max-w-md shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-2xl bg-red-600/10 border border-red-500/20 shadow-red-glow">
            <ShieldCheck className="w-8 h-8 text-xerox-red" />
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Create your XEROX account
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Create your account to access automated threat analysis
          </p>
        </div>

        {serverError && (
          <div
            role="alert"
            className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center gap-2.5"
          >
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{serverError}</span>
          </div>
        )}

        <form onSubmit={handleRegister} noValidate className="space-y-4">
          <Input
            label="Email"
            type="email"
            name="email"
            value={email}
            onChange={handleEmailChange}
            error={fieldErrors.email}
            autoComplete="email"
            placeholder="name@company.com"
            leftIcon={<Mail className="w-4 h-4" />}
          />

          <Input
            label="Password"
            type="password"
            name="password"
            value={password}
            onChange={handlePasswordChange}
            error={fieldErrors.password}
            showPasswordToggle
            autoComplete="new-password"
            placeholder="Minimum 8 characters"
            leftIcon={<Lock className="w-4 h-4" />}
            helperText="Use at least 8 characters, including a number and an uppercase letter or special character."
          />

          <Input
            label="Confirm password"
            type="password"
            name="confirmPassword"
            value={confirmPassword}
            onChange={handleConfirmPasswordChange}
            error={fieldErrors.confirmPassword}
            showPasswordToggle
            autoComplete="new-password"
            placeholder="Repeat password"
            leftIcon={<Lock className="w-4 h-4" />}
          />

          <Button
            type="submit"
            variant="primary"
            fullWidth
            loading={loading}
            loadingText="Creating account..."
            rightIcon={<ArrowRight className="w-4 h-4" />}
          >
            Create account
          </Button>
        </form>

        <div className="pt-2 border-t border-xerox-border-subtle text-center text-xs font-mono text-slate-400">
          Already registered?{" "}
          <Link
            to="/login"
            className="text-red-400 hover:text-red-300 transition-colors font-semibold"
          >
            Sign in
          </Link>
        </div>
      </Card>
    </div>
  );
};

