import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { Session } from "@/types/auth";

interface AuthState {
  session: Session | null;
  isLoading: boolean;
  error: Error | null;

  // Actions
  setSession: (session: Session | null) => void;
  signOut: () => void;
  clearError: () => void;
  setLoading: (isLoading: boolean) => void;
  setError: (error: Error | null) => void;
}

/**
 * Creates the auth store with persistence
 * @param storageKey - Key for localStorage persistence
 */
export const createAuthStore = (
  storageKey: string = "anythink_auth_session"
) => {
  return create<AuthState>()(
    persist(
      (set) => ({
        session: null,
        isLoading: false,
        error: null,

        setSession: (session: Session | null) => {
          set({ session, error: null });
        },

        signOut: () => {
          set({ session: null, error: null });
        },

        clearError: () => {
          set({ error: null });
        },

        setLoading: (isLoading: boolean) => {
          set({ isLoading });
        },

        setError: (error: Error | null) => {
          set({ error });
        },
      }),
      {
        name: storageKey,
        storage: createJSONStorage(() => {
          // Use localStorage for persistence
          if (
            typeof globalThis !== "undefined" &&
            "localStorage" in globalThis
          ) {
            return (globalThis as any).localStorage;
          }
          // Fallback for SSR
          return {
            getItem: () => null,
            setItem: () => {},
            removeItem: () => {},
          };
        }),
        // Only persist the session, not loading/error states
        partialize: (state: AuthState) => ({ session: state.session }),
      }
    )
  );
};
