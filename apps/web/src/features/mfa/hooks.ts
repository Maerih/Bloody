import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ApiError } from "../../api/client";
import { queryKeys } from "../../api/hooks";
import { moduleKeys } from "../../api/moduleHooks";

export interface TotpEnrollment {
  secret: string;
  otpauthUri: string;
}

export interface MfaPolicy {
  requireMfa: boolean;
  usersWithMfa: number;
  usersWithoutMfa: number;
}

const policyKey = ["auth", "mfa-policy"] as const;
const enc = encodeURIComponent;

/** Start (or restart) authenticator setup: a new secret, shown once. */
export function useStartMfaSetup() {
  return useMutation<TotpEnrollment, ApiError, void>({ mutationFn: () => api.post<TotpEnrollment>("/auth/mfa/totp/enroll") });
}

export function useConfirmMfaSetup() {
  const qc = useQueryClient();
  return useMutation<{ mfaEnabled: boolean }, ApiError, string>({
    mutationFn: (code) => api.post("/auth/mfa/totp/confirm", { code }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      void qc.invalidateQueries({ queryKey: policyKey });
    },
  });
}

export function useTurnOffMfa() {
  const qc = useQueryClient();
  return useMutation<{ mfaEnabled: boolean }, ApiError, string>({
    mutationFn: (code) => api.post("/auth/mfa/totp/disable", { code }, { skipStepUp: true }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.me }),
  });
}

export function useMfaPolicy(enabled = true) {
  return useQuery<MfaPolicy, ApiError>({ queryKey: policyKey, queryFn: ({ signal }) => api.get<MfaPolicy>("/auth/mfa/policy", { signal }), enabled });
}

export function useSetMfaPolicy() {
  const qc = useQueryClient();
  return useMutation<{ requireMfa: boolean }, ApiError, boolean>({
    mutationFn: (requireMfa) => api.put("/auth/mfa/policy", { requireMfa }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: policyKey });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
  });
}

/** Administrator reset for someone who lost their phone; they set up a new authenticator at next sign-in. */
export function useResetUserMfa() {
  const qc = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (userId) => api.delete<void>(`/users/${enc(userId)}/mfa`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: moduleKeys.users });
      void qc.invalidateQueries({ queryKey: policyKey });
    },
  });
}
