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

      // Mock getSession to return null (expired)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
      }));

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

      // Wait for async operations - vi.waitFor handles async waiting
      // No need to manually flush timers as it causes infinite loops with intervals

      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
      });

      // Clean up to stop the interval
      unmount();

      // Should not redirect to login
      expect(window.location.href).toBe("");
    });

    it("should redirect to login when session is expired and refresh fails", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100); // Expired 100 seconds ago

      // Setup: expired session in store
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock failed refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: null },
        error: new Error("Refresh failed"),
      });

      // Mock getSession to return null (expired)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
      }));

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

      // Wait for async operations - vi.waitFor handles async waiting
      // No need to manually flush timers as it causes infinite loops with intervals

      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
      });

      // Clean up to stop the interval
      unmount();

      // Should redirect to login after failed refresh
      expect(window.location.href).toBe("/auth/login");
    });

    it("should redirect to login when session is expired and no refresh token exists", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 100, ""); // Expired, no refresh token

      // Setup: expired session in store with no refresh token
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock getSession to return null (expired)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
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

      // Wait for async operations - use real timers temporarily to flush promises
      await act(async () => {
        vi.useRealTimers();
        await new Promise((resolve) => setImmediate(resolve));
        vi.useFakeTimers();
      });

      // Should not attempt refresh (no refresh token)
      expect(mockAuthClient.refreshSession).not.toHaveBeenCalled();

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

      // Wait for async operations - use real timers temporarily to flush promises
      await act(async () => {
        vi.useRealTimers();
        await new Promise((resolve) => setImmediate(resolve));
        vi.useFakeTimers();
      });

      // Should not redirect (we're on auth page)
      expect(window.location.href).toBe("");
    });
  });

  describe("Auto-refresh behavior", () => {
    it("should automatically refresh token when it expires within threshold", async () => {
      const now = Math.floor(Date.now() / 1000);
      const sessionExpiringSoon = createMockSession(now + 30); // Expires in 30 seconds
      const newSession = createMockSession(now + 3600); // Valid for 1 hour
      const mockUser = createMockUser();

      // Setup: session expiring soon in store
      const storeState = (mockStore as any).getState();
      storeState.session = sessionExpiringSoon;
      storeState.user = mockUser;

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock getSession to return session (not expired yet)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: sessionExpiringSoon },
      }));

      const TestComponent = () => {
        return <div>Test</div>;
      };

      const { unmount } = await act(async () => {
        return render(
          <AuthProvider
            authClient={mockAuthClient as AuthClient}
            loginUrl="/auth/login"
            authPrefix="/auth"
            autoRefresh={true}
            refreshThreshold={60}
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Advance time to trigger refresh check
      await act(async () => {
        vi.advanceTimersByTime(35000); // Advance 35 seconds
        // Run only currently pending timers, not ones scheduled by intervals
        vi.runOnlyPendingTimers();
      });

      // Wait for refresh to be called
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
      });

      // Clean up to stop the interval
      unmount();
    });

    it("should use raw session from store for refresh check even when getSession returns null", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredSession = createMockSession(now - 10); // Just expired
      const newSession = createMockSession(now + 3600); // Valid for 1 hour

      // Setup: expired session in store (but still has refresh token)
      const storeState = (mockStore as any).getState();
      storeState.session = expiredSession;
      storeState.user = null;

      // Mock getSession to return null (expired)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
      }));

      // Mock successful refresh
      (mockAuthClient.refreshSession as any) = vi.fn().mockResolvedValue({
        data: { session: newSession },
        error: null,
      });

      // Mock successful user fetch
      (mockAuthClient.fetchUserInfo as any) = vi.fn().mockResolvedValue({
        data: { user: createMockUser() },
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
            autoRefresh={true}
            refreshThreshold={60}
          >
            <TestComponent />
          </AuthProvider>
        );
      });

      // Advance time to trigger refresh check
      await act(async () => {
        vi.advanceTimersByTime(30000); // Advance 30 seconds
        // Run only currently pending timers, not ones scheduled by intervals
        vi.runOnlyPendingTimers();
      });

      // Should still attempt refresh even though getSession returns null
      // because we're using raw session from store
      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
      });

      // Clean up to stop the interval
      unmount();
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

      // Mock getSession to return null (expired)
      (mockAuthClient.getSession as any) = vi.fn(() => ({
        data: { session: null },
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

      // Wait for async operations - vi.waitFor handles async waiting
      // No need to manually flush timers as it causes infinite loops with intervals

      await vi.waitFor(() => {
        expect(mockAuthClient.refreshSession).toHaveBeenCalled();
        expect(mockAuthClient.fetchUserInfo).toHaveBeenCalled();
      });
    });
  });
});
