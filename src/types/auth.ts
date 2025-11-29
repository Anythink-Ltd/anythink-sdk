/**
 * Token pair structure matching the backend API response
 */
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * User structure
 */
export interface User {
  id: number;
  gid: string;
  first_name: string;
  last_name: string;
  email: string;
  created_at: string;
}

/**
 * Session structure for internal use
 */
export interface Session {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at: number;
}

/**
 * Configuration for the auth client
 */
export interface AuthConfig {
  instanceUrl: string;
  orgId: number;
  tokenEndpoint?: string;
  refreshEndpoint?: string;
  changePasswordEndpoint?: string;
  storageKey?: string;
  onSignOut?: () => void;
}

/**
 * Sign in response
 */
export interface SignInResponse {
  data: {
    session: Session | null;
  };
  error: Error | null;
}

/**
 * Refresh response
 */
export interface RefreshResponse {
  data: {
    session: Session | null;
  };
  error: Error | null;
}
