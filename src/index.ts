/**
 * Anythink SDK
 *
 * A reusable Typescript SDK for the Anythink platform.
 */

// Version
export const version = "0.1.0";

// Auth exports
export { AuthClient } from "@/auth/client";
export { createAuthStore } from "@/auth/store";

// Service exports
export { AuthenticatedBaseService } from "@/services/AuthenticatedBaseService";

// Type exports
export type {
  AuthConfig,
  Session,
  SignInResponse,
  RefreshResponse,
  TokenPair,
} from "@/types/auth";
