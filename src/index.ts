/**
 * Anythink SDK
 *
 * A reusable Typescript SDK for the Anythink platform.
 */

// Auth exports
export { AuthClient } from "@/auth/client";
export { createAuthStore } from "@/auth/store";
export { AuthProvider, useAuth } from "@/auth/provider";
export type {
  AuthProviderProps,
  AuthCallbacks,
  AuthContextValue,
} from "@/auth/provider";

// Service exports
export { AuthenticatedBaseService } from "@/services/AuthenticatedBaseService";

// Type exports
export type {
  AuthConfig,
  CookieStorageConfig,
  User,
  Session,
  SignInResponse,
  RefreshResponse,
  TokenPair,
} from "@/types/auth";
