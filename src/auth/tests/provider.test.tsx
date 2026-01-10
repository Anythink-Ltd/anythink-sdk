import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, act } from "@testing-library/react";
import { AuthProvider } from "@/auth/provider";
import type { AuthClient } from "@/auth/client";
import type { Session, User } from "@/types/auth";

describe("AuthProvider - Session Expiration and Refresh", () => {
  let mockAuthClient: Partial<AuthClient>;
  let mockStore: any;
  let mockSetSession: ReturnType<typeof vi.fn>;
  let mockSetUser: ReturnType<typeof vi.fn>;
  let mockSetLoading: ReturnType<typeof vi.fn>;
  let mockSetError: ReturnType<typeof vi.fn>;
  let mockClearError: ReturnType<typeof vi.fn>;
  let mockSignOut: ReturnType<typeof vi.fn>;

  const createMockSession = (
    expiresAt: number,
    refreshToken: string = "refresh_token_123"
  ): Session => ({
    access_token: "access_token_123",
    refresh_token: refreshToken,
    expires_in: 3600,
    expires_at: expiresAt,
  });

  const createMockUser = (): User => ({
    id: 1,
    gid: "gid_123",
    first_name: "Test",
    last_name: "User",
    email: "test@example.com",
    created_at: "2024-01-01T00:00:00Z",
  });

  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();
    vi.useFakeTimers();

    // Create mock store functions
    mockSetSession = vi.fn();
    mockSetUser = vi.fn();
    mockSetLoading = vi.fn();
    mockSetError = vi.fn();
    mockClearError = vi.fn();
    mockSignOut = vi.fn();

    // Create mock store state
    const mockStoreState = {
      session: null as Session | null,
      user: null as User | null,
      isLoading: false,
      error: null as Error | null,
      setSession: mockSetSession,
      setUser: mockSetUser,
      setLoading: mockSetLoading,
      setError: mockSetError,
      clearError: mockClearError,
      signOut: mockSignOut,
    };

    // Create mock store that behaves like a Zustand store
    // Zustand stores are callable functions that accept selectors
    mockStore = vi.fn((selector?: (state: typeof mockStoreState) => any) => {
      if (selector) {
        return selector(mockStoreState);
      }
      return mockStoreState;
    }) as any;

    // Add getState method
    (mockStore as any).getState = vi.fn(() => mockStoreState);
    (mockStore as any).subscribe = vi.fn(() => vi.fn()); // Returns unsubscribe function

    // Create mock AuthClient
    mockAuthClient = {
      getStore: vi.fn(() => mockStore as any),
      getSession: vi.fn(() => ({ data: { session: null } })),
      refreshSession: vi.fn(),
      fetchUserInfo: vi.fn(),
      signOut: vi.fn(),
      register: vi.fn(),
      changePassword: vi.fn(),
      getAccessToken: vi.fn(),
      getRefreshToken: vi.fn(),
    } as unknown as AuthClient;

    // Reset window.location
    Object.defineProperty(window, "location", {
      value: {
        href: "",
        pathname: "/",
      },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("Session expiration handling", () => {
    it("should attempt refresh when session is expired but refresh token exists", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100); // Expired 100 seconds ago
      const newSession = createMockSession(now + 3600); // Valid for 1 hour
      const mockUser = createMockUser();

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock successful user fetch
      (mockAuthClient.fetchUserInfo as any) = vi.fn().mockResolvedValue({
        data: { user: mockUser },
        error: null,
      });

      // Mock getSession to return the expired session (provider checks expiration)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      const { unmount } = await act(async () => {
        return render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalled();
      });

      // Clean up
      unmount();

      // Should not redirect to login (refresh succeeded)
      expect(window.location.href).toBe("");
    });

    it("should redirect to login when session is expired and refresh fails", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100); // Expired 100 seconds ago
      const onTokenRefreshFailed = vi.fn();

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock failed refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: null },
        error: new Error("Refresh failed"),
      });

      // Mock getSession to return the expired session (provider checks expiration)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      const { unmount } = await act(async () => {
        return render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
            callbacks={{ onTokenRefreshFailed }}
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.signOut).toHaveBeenCalled();
      });

      // Clean up
      unmount();

      // Should call the callback
      expect(onTokenRefreshFailed).toHaveBeenCalled();

      // Should redirect to login after failed refresh
      expect(window.location.href).toBe("/auth/login");
    });

    it("should redirect to login when session is expired and no refresh token exists", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100, ""); // Expired, no refresh token
      const onTokenRefreshFailed = vi.fn();

      // Setup: expired session in store with no refresh token
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock getSession to return the expired session (provider checks expiration)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      // Mock failed refresh (client will fail because no refresh token)
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: null },
        error: new Error("No refresh token found"),
      });

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
            callbacks={{ onTokenRefreshFailed }}
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.signOut).toHaveBeenCalled();
      });

      // Should call the callback
      expect(onTokenRefreshFailed).toHaveBeenCalled();

      // Should redirect to login
      expect(window.location.href).toBe("/auth/login");
    });

    it("should not redirect when on auth page even if session is expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100);

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Set pathname to auth page
      Object.defineProperty(window, "location", {
        value: {
          href: "",
          pathname: "/auth/login",
        },
        writable: true,
        configurable: true,
      });

      // Mock getSession (shouldn't be called on auth page, but just in case)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait a bit to ensure no async operations run
      await act(async () => {
        vi.useRealTimers();
        await new Promise((resolve) => setImmediate(resolve));
        vi.useFakeTimers();
      });

      // Should not redirect (we're on auth page)
      expect(window.location.href).toBe("");
      // Should not attempt any auth operations
      expect(mockAuthClient.refreshSession).not.toHaveBeenCalled();
      expect(mockAuthClient.fetchUserInfo).not.toHaveBeenCalled();
    });
  });

  describe("Initialization behavior", () => {
    it("should fetch user info after successful refresh on initialization", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100);
      const newSession = createMockSession(now + 3600);
      const mockUser = createMockUser();

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock successful user fetch
      (mockAuthClient.fetchUserInfo as any) = vi.fn().mockResolvedValue({
        data: { user: mockUser },
        error: null,
      });

      // Mock getSession to return the expired session (provider checks expiration)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalled();
      });
    });

    it("should handle fetchUserInfo error and attempt refresh", async () => {
      const now = Math.floor(Date.now() / 1000);
      const validSession = createMockSession(now + 3600);
      const newSession = createMockSession(now + 7200);
      const mockUser = createMockUser();

      // Setup: valid session in store
      const storeState = (mockStore as any).getState();
      storeState.session = validSession;
      storeState.user = null;

      // Mock getSession to return the valid session
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: validSession },
      }));

      // Mock fetchUserInfo to fail first time
      (mockAuthClient.fetchUserInfo as any) = vi
        .fn()
        .mockResolvedValueOnce({
          data: { user: null },
          error: new Error("Unauthorized"),
        })
        .mockResolvedValueOnce({
          data: { user: mockUser },
          error: null,
        });

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalledTimes(2);
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
      });

      // Should not redirect (refresh and retry succeeded)
      expect(window.location.href).toBe("");
    });

    it("should redirect when fetchUserInfo fails and refresh also fails", async () => {
      const now = Math.floor(Date.now() / 1000);
      const validSession = createMockSession(now + 3600);
      const onTokenRefreshFailed = vi.fn();

      // Setup: valid session in store
      const storeState = (mockStore as any).getState();
      storeState.session = validSession;
      storeState.user = null;

      // Mock getSession to return the valid session
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: validSession },
      }));

      // Mock fetchUserInfo to fail
      (mockAuthClient.fetchUserInfo as any) = vi.fn().mockResolvedValue({
        data: { user: null },
        error: new Error("Unauthorized"),
      });

      // Mock failed refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: null },
        error: new Error("Refresh failed"),
      });

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
            callbacks={{ onTokenRefreshFailed }}
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalled();
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.signOut).toHaveBeenCalled();
      });

      // Should call the callback
      expect(onTokenRefreshFailed).toHaveBeenCalled();

      // Should redirect to login
      expect(window.location.href).toBe("/auth/login");
    });

    it("should redirect when fetchUserInfo fails after successful refresh", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100);
      const newSession = createMockSession(now + 3600);

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock getSession to return the expired session
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: expiredSession },
      }));

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock fetchUserInfo to fail after refresh
      (mockAuthClient.fetchUserInfo as any) = vi.fn().mockResolvedValue({
        data: { user: null },
        error: new Error("Failed to fetch user"),
      });

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalled();
        expect(mockAuthClient.signOut).toHaveBeenCalled();
      });

      // Should redirect to login
      expect(window.location.href).toBe("/auth/login");
    });

    it("should redirect when no session exists", async () => {
      // Setup: no session in store
      const storeState = (mockStore as any).getState();
      storeState.session = null;
      storeState.user = null;

      // Mock getSession to return no session
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
      }));

      // Mock signOut
      (mockAuthClient.signOut as any) = vi.fn().mockResolvedValue({
        error: null,
      });

      const TestComponent = () => {
        return <div>Test</div>;
      };

      await act(async () => {
        render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Wait for async operations
      await vi.waitFor(() => {
        expect(mockAuthClient.signOut).toHaveBeenCalled();
      });

      // Should redirect to login
      expect(window.location.href).toBe("/auth/login");
    });
  });
});
