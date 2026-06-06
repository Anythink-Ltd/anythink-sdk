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
export interface AuthStoreOptions extends CookieStorageOptions {
  storageType?: "cookie" | "sessionStorage" | "localStorage";
}

const safeStorage = (type: "sessionStorage" | "localStorage") => ({
  getItem: (name: string): string | null => {
    if (typeof window === "undefined") return null;
    return window[type].getItem(name);
  },
  setItem: (name: string, value: string): void => {
    if (typeof window === "undefined") return;
    window[type].setItem(name, value);
  },
  removeItem: (name: string): void => {
    if (typeof window === "undefined") return;
    window[type].removeItem(name);
  },
});

/**
 * Creates the auth store with cookie or web storage persistence
 * @param options - Optional store options to override defaults
 */
export const createAuthStore = (options?: AuthStoreOptions) => {
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
        name: options?.name ?? "anythink_auth_session",
        storage: createJSONStorage(() => {
          if (options?.storageType === "sessionStorage") {
            return safeStorage("sessionStorage");
          }
          if (options?.storageType === "localStorage") {
            return safeStorage("localStorage");
          }

          // Default fallback to cookie storage
          return createCookieStorage({
            name: options?.name ?? "anythink_auth_session",
            path: "/",
            secure:
              typeof window !== "undefined" &&
              window.location.protocol === "https:",
            sameSite: "lax",
            ...options, // User-provided options override defaults
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
