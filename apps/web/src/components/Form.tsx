import { clsx } from "clsx";
import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

const CONTROL =
  "w-full rounded border border-line-strong bg-surface px-2 text-base text-fg placeholder:text-fg-subtle focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:cursor-not-allowed disabled:bg-surface-3 disabled:opacity-70 aria-[invalid=true]:border-sev-critical";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return <input ref={ref} className={clsx(CONTROL, "h-8", className)} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...rest }, ref) {
  return (
    <select ref={ref} className={clsx(CONTROL, "h-8 pr-6", className)} {...rest}>
      {children}
    </select>
  );
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={clsx(CONTROL, "min-h-[72px] py-1.5", className)} {...rest} />;
});

export interface FieldProps {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  required?: boolean;
  className?: string;
  /** Render-prop receives the generated id and aria attributes for the control. */
  children: (props: { id: string; "aria-invalid": boolean; "aria-describedby"?: string }) => ReactNode;
}

/** Label + control + hint/error with correct aria wiring. */
export function Field({ label, hint, error, required, className, children }: FieldProps) {
  const id = useId();
  const describedBy = error ? `${id}-error` : hint ? `${id}-hint` : undefined;
  return (
    <div className={clsx("space-y-1", className)}>
      <label htmlFor={id} className="block text-sm font-medium text-fg">
        {label}
        {required ? <span className="ml-0.5 text-sev-critical">*</span> : null}
      </label>
      {children({ id, "aria-invalid": Boolean(error), ...(describedBy ? { "aria-describedby": describedBy } : {}) })}
      {error ? (
        <p id={`${id}-error`} className="text-xs text-sev-critical">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-fg-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function Checkbox({ label, className, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label className={clsx("inline-flex cursor-pointer items-center gap-2 text-base text-fg", className)}>
      <input type="checkbox" className="h-3.5 w-3.5 rounded border-line-strong accent-[rgb(var(--primary))]" {...rest} />
      {label}
    </label>
  );
}
