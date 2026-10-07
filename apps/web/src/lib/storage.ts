import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Safe localStorage access. Storage may be unavailable (private mode, quota, sandboxed iframe);
 * every failure degrades to in-memory state. Only UI preferences are stored here — never
 * tokens, secrets or customer data.
 */
const PREFIX = "bloody.";

export function storageKey(key: string): string {
  return key.startsWith(PREFIX) ? key : PREFIX + key;
}

export function readStorage<T>(key: string, validate?: (value: unknown) => value is T): T | undefined {
  try {
    const raw = globalThis.localStorage?.getItem(storageKey(key));
    if (raw === null || raw === undefined) return undefined;
    const parsed: unknown = JSON.parse(raw);
    if (validate && !validate(parsed)) return undefined;
    return parsed as T;
  } catch {
    return undefined;
  }
}

export function writeStorage(key: string, value: unknown): void {
  try {
    if (value === undefined) globalThis.localStorage?.removeItem(storageKey(key));
    else globalThis.localStorage?.setItem(storageKey(key), JSON.stringify(value));
  } catch {
    /* storage unavailable or full: preference simply isn't persisted */
  }
}

export function removeStorage(key: string): void {
  try {
    globalThis.localStorage?.removeItem(storageKey(key));
  } catch {
    /* ignore */
  }
}

/** useState that persists to localStorage under `key` (re-reads when the key changes). */
export function useLocalStorageState<T>(
  key: string,
  initial: T,
  validate?: (value: unknown) => value is T,
): [T, (next: T | ((prev: T) => T)) => void] {
  const [state, setState] = useState<T>(() => readStorage<T>(key, validate) ?? initial);
  const keyRef = useRef(key);
  const initialRef = useRef(initial);
  initialRef.current = initial;
  const validateRef = useRef(validate);
  validateRef.current = validate;

  useEffect(() => {
    if (keyRef.current !== key) {
      keyRef.current = key;
      setState(readStorage<T>(key, validateRef.current) ?? initialRef.current);
    }
  }, [key]);

  const update = useCallback(
    (next: T | ((prev: T) => T)) => {
      setState((prev) => {
        const value = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        writeStorage(keyRef.current, value);
        return value;
      });
    },
    [],
  );

  return [state, update];
}

export const isString = (v: unknown): v is string => typeof v === "string";
export const isNumber = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
export const isBoolean = (v: unknown): v is boolean => typeof v === "boolean";
export function isOneOf<T extends string>(values: readonly T[]) {
  return (v: unknown): v is T => typeof v === "string" && (values as readonly string[]).includes(v);
}
