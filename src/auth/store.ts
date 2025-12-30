import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { Session, User } from "@/types/auth";
import {
  createCookieStorage,
  type CookieStorageOptions,
} from "@/auth/cookieStorage";

interface AuthState {
  session: Session | null;
  user: User | null;
  isLoading: boolean;
  error: Error | null;

  // Actions
  setSession: (session: Session | null) => void;
  setUser: (user: User | null) => void;
  signOut: () => void;
  clearError: () => void;
  setLoading: (isLoading: boolean) => void;
  setError: (error: Error | null) => void;
}

/**
 * Creates the auth store with cookie-based persistence
 * Always uses cookies with default values, never localStorage
 * @param storageKey - Key for cookie storage (cookie name)
 * @param cookieOptions - Optional cookie configuration options to override defaults
 */
export const createAuthStore = (cookieOptions?: CookieStorageOptions) => {
  return create<AuthState>()(
    persist(
      (set) => ({
        session: null,
        user: null,
        isLoading: false,
        error: null,

        setSession: (session: Session | null) => {
          set({ session, error: null });
        },

        setUser: (user: User | null) => {
          set({ user });
        },

        signOut: () => {
          set({ session: null, user: null, error: null });
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
        name: cookieOptions?.name ?? "anythink_auth_session",
        storage: createJSONStorage(() => {
          // Always use cookie storage with defaults
          // Defaults: path='/', secure=true (if HTTPS), sameSite='lax'
          return createCookieStorage({
            name: cookieOptions?.name ?? "anythink_auth_session",
            path: "/",
            secure:
              typeof window !== "undefined" &&
              window.location.protocol === "https:",
            sameSite: "lax",
            ...cookieOptions, // User-provided options override defaults
          });
        }),
        // Only persist the session and user, not loading/error states
        partialize: (state: AuthState) => ({
          session: state.session,
          user: state.user,
        }),
      }
    )
  );
};
