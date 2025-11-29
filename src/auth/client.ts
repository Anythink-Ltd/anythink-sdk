import axios, { AxiosError, AxiosInstance } from "axios";
import type {
  AuthConfig,
  Session,
  SignInResponse,
  RefreshResponse,
  TokenPair,
} from "@/types/auth";
import { createAuthStore } from "@/auth/store";

/**
 * Auth client for handling authentication with the Anythink API
 */
export class AuthClient {
  private store: ReturnType<typeof createAuthStore>;
  private config: Required<AuthConfig>;
  private onSessionChanged?: (session: Session | null) => void;
  private axiosClient: AxiosInstance;

  constructor(
    config: AuthConfig & {
      onSessionChanged?: (session: Session | null) => void;
    }
  ) {
    this.config = {
      tokenEndpoint: "/auth/v1/token",
      refreshEndpoint: "/auth/v1/refresh",
      changePasswordEndpoint: "/users/me/password",
      storageKey: "anythink_auth_session",
      onSignOut: () => {
        return;
      },
      ...config,
    };

    this.store = createAuthStore(this.config.storageKey);

    // Create axios instance with base URL
    this.axiosClient = axios.create({
      baseURL: this.config.instanceUrl,
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (typeof config.onSessionChanged === "function") {
      this.onSessionChanged = config.onSessionChanged;
    }
  }

  /**
   * Set the onSessionChanged handler.
   * @param handler Callback fired whenever the session changes
   */
  setOnSessionChanged(
    handler: ((session: Session | null) => void) | undefined
  ) {
    this.onSessionChanged = handler;
  }

  /**
   * Internal helper to call the session-changed handler, if present.
   */
  private _callSessionChanged(session: Session | null) {
    if (typeof this.onSessionChanged === "function") {
      try {
        this.onSessionChanged(session);
      } catch (e) {
        // Avoid throwing in userland
        console.warn("onSessionChanged threw:", e);
      }
    }
  }

  /**
   * Sign in with email and password
   * @param email User email
   * @param password User password
   * @param orgId Optional organization ID
   * @returns Session object with tokens
   */
  async signIn(
    email: string,
    password: string,
    orgId?: number
  ): Promise<SignInResponse> {
    try {
      this.store.getState().setLoading(true);
      this.store.getState().clearError();

      const params = orgId ? { org_id: orgId.toString() } : undefined;

      // Always expect snake_case fields from the API
      const response = await this.axiosClient.post<TokenPair>(
        this.config.tokenEndpoint,
        { email, password },
        { params }
      );

      const tokenPair = response.data;

      const session: Session = {
        access_token: tokenPair.access_token,
        refresh_token: tokenPair.refresh_token,
        expires_in: tokenPair.expires_in,
        expires_at: Math.floor(Date.now() / 1000) + tokenPair.expires_in,
      };

      this.store.getState().setSession(session);
      this._callSessionChanged(session); // Call hook here
      this.store.getState().setLoading(false);

      return { data: { session }, error: null };
    } catch (error) {
      let authError: Error;
      if (error instanceof AxiosError) {
        const errorMessage =
          typeof error.response?.data === "string"
            ? error.response.data
            : error.response?.data?.message ||
              error.message ||
              "Invalid email or password";
        authError = new Error(errorMessage);
      } else {
        authError =
          error instanceof Error ? error : new Error("Sign in failed");
      }
      this.store.getState().setError(authError);
      this.store.getState().setLoading(false);
      this.store.getState().setSession(null);
      this._callSessionChanged(null); // Call hook for failed sign in

      return {
        data: { session: null },
        error: authError,
      };
    }
  }

  /**
   * Register a new user
   * @param firstName User's first name
   * @param lastName User's last name
   * @param email User's email
   * @param password User's password
   * @returns Error object or null if successful
   */
  async register(
    firstName: string,
    lastName: string,
    email: string,
    password: string
  ): Promise<{ error: Error | null }> {
    try {
      await this.axiosClient.post("/auth/v1/register", {
        first_name: firstName,
        last_name: lastName,
        email,
        password,
        org_id: this.config.orgId,
      });
      return { error: null };
    } catch (error) {
      let authError: Error;
      if (error instanceof AxiosError) {
        const errorMessage =
          typeof error.response?.data === "string"
            ? error.response.data
            : error.response?.data?.message ||
              error.message ||
              "Failed to register";
        authError = new Error(errorMessage);
      } else {
        authError =
          error instanceof Error ? error : new Error("Failed to register");
      }
      return {
        error: authError,
      };
    }
  }

  /**
   * Refresh the access token using the refresh token
   * @returns Session object with new tokens
   */
  async refreshSession(): Promise<RefreshResponse> {
    const { session } = this.store.getState();
    if (!session?.refresh_token) {
      const error = new Error("No refresh token found");
      this.store.getState().setError(error);
      return {
        data: { session: null },
        error,
      };
    }

    try {
      this.store.getState().setLoading(true);
      this.store.getState().clearError();

      const response = await this.axiosClient.post<TokenPair>(
        this.config.refreshEndpoint,
        { token: session.refresh_token }
      );

      const tokenPair = response.data;

      const newSession: Session = {
        access_token: tokenPair.access_token,
        refresh_token: tokenPair.refresh_token,
        expires_in: tokenPair.expires_in,
        expires_at: Math.floor(Date.now() / 1000) + tokenPair.expires_in,
      };

      this.store.getState().setSession(newSession);
      this._callSessionChanged(newSession); // Call here
      this.store.getState().setLoading(false);

      return { data: { session: newSession }, error: null };
    } catch (error) {
      // Clear invalid tokens
      this.store.getState().setSession(null);
      this._callSessionChanged(null); // Call hook here on null-out
      this.store.getState().setLoading(false);

      let authError: Error;
      if (error instanceof AxiosError) {
        const errorMessage =
          typeof error.response?.data === "string"
            ? error.response.data
            : error.response?.data?.message ||
              error.message ||
              "Invalid refresh token";
        authError = new Error(errorMessage);
      } else {
        authError =
          error instanceof Error ? error : new Error("Token refresh failed");
      }
      this.store.getState().setError(authError);

      return {
        data: { session: null },
        error: authError,
      };
    }
  }

  /**
   * Get the current session
   * @returns Session object or null if not authenticated
   */
  getSession(): { data: { session: Session | null } } {
    const session = this.store.getState().session;

    // Check if session is expired
    // expires_at is in seconds (Unix timestamp), Date.now() is in milliseconds
    if (
      session &&
      session.expires_at &&
      Date.now() >= session.expires_at * 1000
    ) {
      // Session expired, return null
      // The caller should handle refresh if needed
      return { data: { session: null } };
    }

    return { data: { session } };
  }

  /**
   * Set session from tokens (useful for OAuth flows or token exchange)
   * @param accessToken Access token
   * @param refreshToken Refresh token
   * @param expiresIn Expiration time in seconds
   */
  async setSession({
    access_token,
    refresh_token,
    expires_in,
  }: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }): Promise<{ error: Error | null }> {
    try {
      const session: Session = {
        access_token,
        refresh_token,
        expires_in,
        expires_at: Math.floor(Date.now() / 1000) + expires_in,
      };
      this.store.getState().setSession(session);
      this._callSessionChanged(session); // Call here
      return { error: null };
    } catch (error) {
      this._callSessionChanged(null); // Defensive, though only on explicit error
      return {
        error:
          error instanceof Error ? error : new Error("Failed to set session"),
      };
    }
  }

  /**
   * Change the current user's password
   * @param currentPassword Current password
   * @param newPassword New password
   * @returns Error object or null if successful
   */
  async changePassword(
    currentPassword: string,
    newPassword: string
  ): Promise<{ error: Error | null }> {
    try {
      const token = this.getAccessToken();
      if (!token) {
        throw new Error("No access token found");
      }
      await this.axiosClient.post(
        this.config.changePasswordEndpoint,
        {
          current_password: currentPassword,
          new_password: newPassword,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      return { error: null };
    } catch (error) {
      let authError: Error;
      if (error instanceof AxiosError) {
        const errorMessage =
          typeof error.response?.data === "string"
            ? error.response.data
            : error.response?.data?.message ||
              error.message ||
              "Failed to change password";
        authError = new Error(errorMessage);
      } else {
        authError =
          error instanceof Error
            ? error
            : new Error("Failed to change password");
      }
      return {
        error: authError,
      };
    }
  }

  /**
   * Sign out and clear session
   */
  async signOut(): Promise<{ error: null }> {
    this.store.getState().signOut();
    this._callSessionChanged(null); // Call on sign out
    if (this.config.onSignOut) {
      this.config.onSignOut();
    }
    return { error: null };
  }

  /**
   * Get the current access token
   */
  getAccessToken(): string | null {
    const session = this.store.getState().session;
    if (!session) return null;

    // Check if expired
    // expires_at is in seconds (Unix timestamp), Date.now() is in milliseconds
    if (session.expires_at && Date.now() >= session.expires_at * 1000) {
      return null;
    }

    return session.access_token;
  }

  /**
   * Get the current refresh token
   */
  getRefreshToken(): string | null {
    return this.store.getState().session?.refresh_token || null;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const session = this.store.getState().session;
    if (!session) return false;

    // Check if expired
    // expires_at is in seconds (Unix timestamp), Date.now() is in milliseconds
    if (session.expires_at && Date.now() >= session.expires_at * 1000) {
      return false;
    }

    return true;
  }

  /**
   * Get the Zustand store (for React hooks)
   */
  getStore(): ReturnType<typeof createAuthStore> {
    return this.store;
  }
}
