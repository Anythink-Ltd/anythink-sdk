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
 * Cookie storage configuration options
 */
export interface CookieStorageConfig {
  /**
   * Cookie name (default: 'anythink_auth_session')
   */
  name?: string;
  /**
   * Cookie domain (optional)
   */
  domain?: string;
  /**
   * Cookie path (default: '/')
   */
  path?: string;
  /**
   * Whether to use Secure flag (HTTPS only, default: true in production)
   */
  secure?: boolean;
  /**
   * SameSite attribute (default: 'lax')
   */
  sameSite?: "strict" | "lax" | "none";
}

/**
 * Configuration for the auth client
 */
export interface AuthConfig {
  instanceUrl: string;
  orgId: number;
  cookieStorage?: CookieStorageConfig;
  tokenEndpoint?: string;
  refreshEndpoint?: string;
  registerEndpoint?: string;
  changePasswordEndpoint?: string;
  logoutEndpoint?: string;
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
