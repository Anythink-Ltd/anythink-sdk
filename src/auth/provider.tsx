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
   * Whether to automatically refresh tokens before they expire
   * @default true
   */
  autoRefresh?: boolean;
  /**
   * How many seconds before expiration to refresh the token
   * @default 60
   */
  refreshThreshold?: number;
  /**
   * URL to redirect to when user is not authenticated or token refresh fails
   */
  loginUrl?: string;
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
  autoRefresh = true,
  refreshThreshold = 60,
  loginUrl,
  children,
}: AuthProviderProps) {
  const store = authClient.getStore();
  const session = store((state) => state.session);
  const user = store((state) => state.user);
  const isLoading = store((state) => state.isLoading);
  const error = store((state) => state.error);
  const refreshTimerRef = useRef<NodeJS.Timeout | null>(null);
  const isRefreshingRef = useRef(false);
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
   * Redirect to login URL if configured
   */
  const redirectToLogin = useCallback(() => {
    if (loginUrl && typeof window !== "undefined") {
      window.location.href = loginUrl;
    }
  }, [loginUrl]);

  /**
   * Refresh token if needed
   */
  const refreshTokenIfNeeded = useCallback(async () => {
    if (isRefreshingRef.current) {
      return;
    }

    const currentSession = authClient.getSession().data.session;
    if (!currentSession || !currentSession.expires_at) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = currentSession.expires_at - now;

    // Refresh if token expires within the threshold or is already expired
    if (timeUntilExpiry <= refreshThreshold) {
      isRefreshingRef.current = true;
      try {
        const { data, error: refreshError } = await authClient.refreshSession();
        if (refreshError || !data.session) {
          // Refresh failed, call callback if provided
          if (callbacks?.onTokenRefreshFailed) {
            await callbacks.onTokenRefreshFailed();
          }
          // Redirect to login if configured
          redirectToLogin();
        }
      } catch (err) {
        // Refresh failed, call callback if provided
        if (callbacks?.onTokenRefreshFailed) {
          await callbacks.onTokenRefreshFailed();
        }
        // Redirect to login if configured
        redirectToLogin();
      } finally {
        isRefreshingRef.current = false;
      }
    }
  }, [authClient, refreshThreshold, callbacks, redirectToLogin]);

  /**
   * Initialize auth state on mount - load user details if session exists
   */
  useEffect(() => {
    if (hasInitializedRef.current) {
      return;
    }
    hasInitializedRef.current = true;

    let isMounted = true;

    const initializeAuth = async () => {
      try {
        const currentSession = authClient.getSession().data.session;

        // If no session or session is expired, redirect to login
        if (!currentSession || !currentSession.expires_at) {
          if (loginUrl && isMounted) {
            redirectToLogin();
          }
          return;
        }

        // Check if session is expired
        // Note: getSession() already returns null if expired, but we check explicitly
        // in case the session exists but is expired
        const now = Math.floor(Date.now() / 1000);
        if (currentSession.expires_at <= now) {
          // Try to refresh the session
          const { data, error: refreshError } =
            await authClient.refreshSession();
          if (!isMounted) {
            return;
          }
          if (refreshError || !data.session) {
            // Refresh failed, redirect to login
            if (loginUrl) {
              redirectToLogin();
            }
            return;
          }
        }

        // Session is valid, fetch user details
        const { error: userError } = await authClient.fetchUserInfo();
        if (!isMounted) {
          return;
        }
        if (userError) {
          // If fetching user info fails, it might be an invalid token
          // Try to refresh once more
          const { data, error: refreshError } =
            await authClient.refreshSession();
          if (!isMounted) {
            return;
          }
          if (refreshError || !data.session) {
            // Refresh failed, redirect to login
            if (loginUrl) {
              redirectToLogin();
            }
            return;
          }
          // Retry fetching user info after refresh
          const { error: retryError } = await authClient.fetchUserInfo();
          if (!isMounted) {
            return;
          }
          if (retryError && loginUrl) {
            // If retry also fails, redirect to login
            redirectToLogin();
          }
        }
      } catch (error) {
        // Handle any unexpected errors
        if (isMounted && loginUrl) {
          redirectToLogin();
        }
      }
    };

    initializeAuth();

    return () => {
      isMounted = false;
    };
  }, [authClient, loginUrl, redirectToLogin]);

  /**
   * Setup automatic token refresh
   */
  useEffect(() => {
    if (!autoRefresh || !session || !session.expires_at) {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
      return;
    }

    // Clear any existing timer
    if (refreshTimerRef.current) {
      clearInterval(refreshTimerRef.current);
    }

    // Set up timer to check and refresh token
    const checkAndRefresh = () => {
      refreshTokenIfNeeded();
    };

    // Initial check
    checkAndRefresh();

    // Set up interval to check periodically (every 30 seconds)
    refreshTimerRef.current = setInterval(checkAndRefresh, 30000);

    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [session, autoRefresh, refreshThreshold, refreshTokenIfNeeded]);

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
