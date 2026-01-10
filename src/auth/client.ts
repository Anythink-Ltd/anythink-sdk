import axios, { AxiosError, AxiosInstance } from "axios";
import type {
  AuthConfig,
  Session,
  SignInResponse,
  RefreshResponse,
  TokenPair,
  User,
} from "@/types/auth";
import { createAuthStore } from "@/auth/store";

/**
 * Auth client for handling authentication with the Anythink API
 */
export class AuthClient {
  private store: ReturnType<typeof createAuthStore>;
  private config: AuthConfig;
  private axiosClient: AxiosInstance;

  constructor(config: AuthConfig) {
    this.config = config;
    this.store = createAuthStore({
      name: this.config.cookieStorage?.name ?? "anythink_auth_session",
      domain: this.config.cookieStorage?.domain,
      path: this.config.cookieStorage?.path,
      secure: this.config.cookieStorage?.secure,
      sameSite: this.config.cookieStorage?.sameSite,
    });

    // Create axios instance with base URL
    this.axiosClient = axios.create({
      baseURL: this.config.instanceUrl,
      headers: {
        "Content-Type": "application/json",
      },
    });
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
        this.config.tokenEndpoint ?? `/org/${this.config.orgId}/auth/v1/token`,
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
      this.store.getState().setLoading(false);

      // Fetch user info after successful sign in
      await this.fetchUserInfo();

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
      await this.axiosClient.post(
        this.config.registerEndpoint ??
          `/org/${this.config.orgId}/auth/v1/register`,
        {
          first_name: firstName,
          last_name: lastName,
          email,
          password,
          org_id: this.config.orgId,
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
        this.config.refreshEndpoint ??
          `/org/${this.config.orgId}/auth/v1/refresh`,
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
      this.store.getState().setLoading(false);

      // Fetch user info after successful token refresh
      await this.fetchUserInfo();

      return { data: { session: newSession }, error: null };
    } catch (error) {
      // Clear invalid tokens
      this.store.getState().setSession(null);
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

      // Fetch user info after setting session
      await this.fetchUserInfo();

      return { error: null };
    } catch (error) {
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
        this.config.changePasswordEndpoint ??
          `/org/${this.config.orgId}/users/me/password`,
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
   * Invalidates the refresh token on the server and clears local session
   * @returns Error object or null if successful
   */
  async signOut(): Promise<{ error: Error | null }> {
    const refreshToken = this.getRefreshToken();

    // Always clear local session first
    this.store.getState().signOut();

    // If we have a refresh token, try to invalidate it on the server
    // This is best practice for security - prevents token reuse
    if (refreshToken) {
      try {
        await this.axiosClient.post(
          this.config.logoutEndpoint ??
            `/org/${this.config.orgId}/auth/v1/logout`,
          {
            token: refreshToken,
          }
        );
      } catch (error) {
        // If the API call fails, we've already cleared local session
        // Log the error but don't fail the sign out operation
        // The token may already be invalid or expired, which is fine
        if (error instanceof AxiosError) {
          // Only log if it's not a 401/404 (token already invalid/not found)
          if (
            error.response?.status !== 401 &&
            error.response?.status !== 404
          ) {
            console.warn(
              "Failed to invalidate refresh token on server:",
              error.message
            );
          }
        }
        // Return null error - sign out succeeded locally even if server call failed
        return { error: null };
      }
    }

    return { error: null };
  }

  /**
   * Get the current access token
   */
  getAccessToken(): string | null {
    const session = this.store.getState().session;
    if (!session) return null;
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
   * Fetch user information from the API
   * @returns User object or null if failed
   */
  async fetchUserInfo(): Promise<{
    data: { user: User | null };
    error: Error | null;
  }> {
    const token = this.getAccessToken();
    if (!token) {
      return {
        data: { user: null },
        error: new Error("No access token found"),
      };
    }

    try {
      const response = await this.axiosClient.get<User>(
        `/org/${this.config.orgId}/users/me`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const user = response.data;
      this.store.getState().setUser(user);

      return { data: { user }, error: null };
    } catch (error) {
      let authError: Error;
      if (error instanceof AxiosError) {
        const errorMessage =
          typeof error.response?.data === "string"
            ? error.response.data
            : error.response?.data?.message ||
              error.message ||
              "Failed to fetch user information";
        authError = new Error(errorMessage);
      } else {
        authError =
          error instanceof Error
            ? error
            : new Error("Failed to fetch user information");
      }
      // Don't set error in store for user fetch failures - it's not critical
      return {
        data: { user: null },
        error: authError,
      };
    }
  }

  /**
   * Get the current user
   * @returns User object or null if not available
   */
  getUser(): User | null {
    return this.store.getState().user;
  }

  /**
   * Get the Zustand store (for React hooks)
   */
  getStore(): ReturnType<typeof createAuthStore> {
    return this.store;
  }
}
