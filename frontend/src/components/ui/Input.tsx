import React, { forwardRef, useId, useState } from "react";
import { AlertCircle, Eye, EyeOff } from "lucide-react";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  labelClassName?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  showPasswordToggle?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      labelClassName,
      error,
      helperText,
      leftIcon,
      rightIcon,
      showPasswordToggle = false,
      id: customId,
      className = "",
      disabled,
      type,
      ...props
    },
    ref
  ) => {
    const [isPasswordVisible, setIsPasswordVisible] = useState(false);
    const effectiveType = showPasswordToggle
      ? isPasswordVisible
        ? "text"
        : "password"
      : type;

    const generatedId = useId();
    const id = customId || generatedId;
    const errorId = `${id}-error`;
    const helperId = `${id}-helper`;

    return (
      <div className="w-full space-y-1.5">
        {label && (
          <label
            htmlFor={id}
            className={
              labelClassName ||
              "block text-xs font-mono font-semibold text-slate-300 tracking-wider uppercase"
            }
          >
            {label}
          </label>
        )}
        <div className="relative flex items-center">
          {leftIcon && (
            <div className="absolute left-3.5 flex items-center pointer-events-none text-slate-400">
              {leftIcon}
            </div>
          )}
          <input
            ref={ref}
            id={id}
            type={effectiveType}
            disabled={disabled}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? errorId : helperText ? helperId : undefined}
            className={`w-full h-11 px-4 rounded-xl bg-xerox-surface border text-sm text-slate-100 placeholder-slate-500 font-sans transition-all duration-200 outline-none focus:ring-2 focus:ring-xerox-red/60 focus:border-xerox-red disabled:opacity-50 disabled:bg-slate-900/50 disabled:cursor-not-allowed ${
              leftIcon ? "pl-10" : ""
            } ${showPasswordToggle || rightIcon ? "pr-11" : ""} ${
              error
                ? "border-red-500/80 bg-red-950/10 focus:ring-red-500"
                : "border-xerox-border hover:border-xerox-border-highlight"
            } ${className}`}
            {...props}
          />
          {showPasswordToggle ? (
            <button
              type="button"
              onClick={() => setIsPasswordVisible((prev) => !prev)}
              aria-label={isPasswordVisible ? "Hide password" : "Show password"}
              aria-pressed={isPasswordVisible}
              className="absolute right-1.5 p-2 rounded-lg text-slate-400 hover:text-slate-200 focus:outline-none focus:ring-1 focus:ring-xerox-red transition-colors flex items-center justify-center min-w-[40px] min-h-[40px] touch-manipulation cursor-pointer select-none"
            >
              {isPasswordVisible ? (
                <EyeOff className="w-4 h-4" aria-hidden="true" />
              ) : (
                <Eye className="w-4 h-4" aria-hidden="true" />
              )}
            </button>
          ) : rightIcon ? (
            <div className="absolute right-3.5 flex items-center text-slate-400">
              {rightIcon}
            </div>
          ) : null}
        </div>
        {error && (
          <p
            id={errorId}
            role="alert"
            className="text-xs font-mono text-red-400 flex items-center gap-1.5 mt-1"
          >
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </p>
        )}
        {!error && helperText && (
          <p id={helperId} className="text-xs font-mono text-slate-400 mt-1">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";
