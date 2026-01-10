import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useCallback,
  useMemo,
  type ReactNode,
} from "react";
import { AuthClient } from "@/auth/client";
import type {
  Session,
  SignInResponse,
  RefreshResponse,
  User,
} from "@/types/auth";

/**
 * Callback functions for auth events
 */
export interface AuthCallbacks {
  /**
   * Called after successful sign in
   */
  onSignIn?: (session: Session) => void | Promise<void>;
  /**
   * Called after sign out
   */
  onSignOut?: () => void | Promise<void>;
  /**
   * Called when token refresh fails and user is signed out
   */
  onTokenRefreshFailed?: () => void | Promise<void>;
}

/**
 * Auth context value
 */
export interface AuthContextValue {
  /**
   * Current session
   */
  session: Session | null;
  /**
   * Current user information
   */
  user: User | null;
  /**
   * Whether auth operations are in progress
   */
  isLoading: boolean;
  /**
   * Current error, if any
   */
  error: Error | null;
  /**
   * Whether user is authenticated
   */
  isAuthenticated: boolean;
  /**
   * Sign in with email and password
   */
  signIn: (
    email: string,
    password: string,
    orgId?: number
  ) => Promise<SignInResponse>;
  /**
   * Sign out and clear session
   */
  signOut: () => Promise<{ error: Error | null }>;
  /**
   * Register a new user
   */
  register: (
    firstName: string,
    lastName: string,
    email: string,
    password: string
  ) => Promise<{ error: Error | null }>;
  /**
   * Change password
   */
  changePassword: (
    currentPassword: string,
    newPassword: string
  ) => Promise<{ error: Error | null }>;
  /**
   * Refresh the session token
   */
  refreshSession: () => Promise<RefreshResponse>;
  /**
   * Get the current access token
   */
  getAccessToken: () => string | null;
  /**
   * Get the current refresh token
   */
  getRefreshToken: () => string | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Props for AuthProvider
 */
export interface AuthProviderProps {
  /**
   * AuthClient instance
   */
  authClient: AuthClient;
  /**
   * Optional callbacks for auth events
   */
  callbacks?: AuthCallbacks;
  /**
   * URL to redirect to when user is not authenticated or token refresh fails
   */
  loginUrl: string;
  /**
   * Path prefix for auth pages (e.g., "/auth"). Pages starting with this prefix
   * will skip session checks and redirects
   */
  authPrefix: string;
  /**
   * Child components
   */
  children: ReactNode;
}

/**
 * AuthProvider component that wraps your app and provides auth state
 */
export function AuthProvider({
  authClient,
  callbacks,
  loginUrl,
  authPrefix,
  children,
}: AuthProviderProps) {
  const store = authClient.getStore();
  const session = store((state) => state.session);
  const user = store((state) => state.user);
  const isLoading = store((state) => state.isLoading);
  const error = store((state) => state.error);
  const hasInitializedRef = useRef(false);

  // Check if authenticated (reactive to session changes)
  const isAuthenticated = useMemo(() => {
    if (!session) return false;
    if (session.expires_at && Date.now() >= session.expires_at * 1000) {
      return false;
    }
    return true;
  }, [session]);

  /**
   * Check if current pathname is an auth page
   */
  const isAuthPage = useCallback((): boolean => {
    if (!authPrefix || typeof window === "undefined") {
      return false;
    }
    const pathname = window.location.pathname;
    return pathname.startsWith(authPrefix);
  }, [authPrefix]);

  /**
   * Redirect to login URL if configured and not on auth page
   */
  const redirectToLogin = useCallback(() => {
    if (loginUrl && typeof window !== "undefined" && !isAuthPage()) {
      window.location.href = loginUrl;
    }
  }, [loginUrl, isAuthPage]);

  /**
   * Sign in wrapper with callback support
   */
  const signIn = useCallback(
    async (
      email: string,
      password: string,
      orgId?: number
    ): Promise<SignInResponse> => {
      const result = await authClient.signIn(email, password, orgId);
      if (result.data.session && !result.error && callbacks?.onSignIn) {
        await callbacks.onSignIn(result.data.session);
      }
      return result;
    },
    [authClient, callbacks]
  );

  /**
   * Sign out wrapper with callback support
   */
  const signOut = useCallback(async (): Promise<{ error: Error | null }> => {
    const result = await authClient.signOut();
    if (!result.error && callbacks?.onSignOut) {
      await callbacks.onSignOut();
    }
    return result;
  }, [authClient, callbacks]);

  /**
   * Initialize auth state on mount - check session and load user details
   */
  useEffect(() => {
    // Prevent multiple initialization attempts
    if (hasInitializedRef.current) {
      return;
    }
    hasInitializedRef.current = true;

    // Skip initialization for auth pages
    if (isAuthPage()) {
      return;
    }

    let isMounted = true;

    const initializeAuth = async () => {
      try {
        // Get initial session
        const {
          data: { session: initialSession },
        } = authClient.getSession();

        // Check if we have a valid access token
        const hasValidToken =
          initialSession?.access_token &&
          (!initialSession.expires_at ||
            Date.now() < initialSession.expires_at * 1000);

        if (hasValidToken) {
          // Token is valid, fetch user info
          const { error: userError } = await authClient.fetchUserInfo();
          if (!isMounted) {
            return;
          }

          if (userError) {
            // If fetching user info fails, token might be invalid
            // Try to refresh once
            const { data, error: refreshError } =
              await authClient.refreshSession();
            if (!isMounted) {
              return;
            }

            if (data.session?.access_token && !refreshError) {
              // Refresh succeeded, retry fetching user info
              const { error: retryError } = await authClient.fetchUserInfo();
              if (!isMounted) {
                return;
              }

              if (retryError && loginUrl) {
                // Retry failed, sign out and redirect to login
                await signOut();
                redirectToLogin();
              }
            } else {
              // Refresh failed, call callback if provided
              if (callbacks?.onTokenRefreshFailed) {
                await callbacks.onTokenRefreshFailed();
              }
              // Sign out and redirect to login
              await signOut();
              redirectToLogin();
            }
          }
          return;
        }

        // Token is expired or missing - check if we can refresh
        if (
          initialSession?.access_token &&
          initialSession.expires_at &&
          Date.now() >= initialSession.expires_at * 1000
        ) {
          // Session exists but expired; try to refresh
          const { data, error: refreshError } =
            await authClient.refreshSession();
          if (!isMounted) {
            return;
          }

          if (data.session?.access_token && !refreshError) {
            // Refresh succeeded, fetch user info
            const { error: userError } = await authClient.fetchUserInfo();
            if (!isMounted) {
              return;
            }

            if (userError && loginUrl) {
              // User fetch failed after refresh, sign out and redirect
              await signOut();
              redirectToLogin();
            }
          } else {
            // Refresh failed, call callback if provided
            if (callbacks?.onTokenRefreshFailed) {
              await callbacks.onTokenRefreshFailed();
            }
            // Sign out and redirect to login
            await signOut();
            redirectToLogin();
          }
          return;
        }

        // No access token at all - not authenticated
        if (loginUrl) {
          await signOut();
          redirectToLogin();
        }
      } catch (error) {
        // Handle any unexpected errors
        console.error("[AuthProvider] Initialization error:", error);
        if (isMounted && loginUrl) {
          await signOut();
          redirectToLogin();
        }
      }
    };

    initializeAuth();

    return () => {
      isMounted = false;
    };
  }, [authClient, signOut, redirectToLogin, isAuthPage, loginUrl, callbacks]);

  const contextValue: AuthContextValue = {
    session,
    user,
    isLoading,
    error,
    isAuthenticated,
    signIn,
    signOut,
    register: authClient.register.bind(authClient),
    changePassword: authClient.changePassword.bind(authClient),
    refreshSession: authClient.refreshSession.bind(authClient),
    getAccessToken: authClient.getAccessToken.bind(authClient),
    getRefreshToken: authClient.getRefreshToken.bind(authClient),
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

/**
 * Hook to access auth context
 * @throws Error if used outside AuthProvider
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
