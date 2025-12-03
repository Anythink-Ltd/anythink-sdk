/**
 * Anythink SDK
 *
 * A reusable Typescript SDK for the Anythink platform.
 */

// Auth exports
export { AuthClient } from "@/auth/client";
export { createAuthStore } from "@/auth/store";

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
