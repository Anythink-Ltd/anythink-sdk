/**
 * Cookie storage adapter that implements the same interface as localStorage
 * for use with Zustand's persist middleware.
 */
export interface CookieStorageOptions {
  /**
   * Cookie name/key
   */
  name: string;
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
  /**
   * Maximum age in seconds (optional, for expiration)
   */
  maxAge?: number;
}

/**
 * Creates a cookie storage adapter compatible with Zustand's persist middleware
 */
export function createCookieStorage(options: CookieStorageOptions) {
  const {
    domain,
    path = "/",
    secure = typeof window !== "undefined" &&
      window.location.protocol === "https:",
    sameSite = "lax",
  } = options;

  /**
   * Get a cookie value by name
   */
  function getCookie(cookieName: string): string | null {
    if (typeof document === "undefined") {
      return null;
    }

    const nameEQ = cookieName + "=";
    const cookies = document.cookie.split(";");

    for (let i = 0; i < cookies.length; i++) {
      let cookie = cookies[i];
      while (cookie.charAt(0) === " ") {
        cookie = cookie.substring(1, cookie.length);
      }
      if (cookie.indexOf(nameEQ) === 0) {
        return decodeURIComponent(
          cookie.substring(nameEQ.length, cookie.length)
        );
      }
    }
    return null;
  }

  /**
   * Set a cookie value
   */
  function setCookie(
    cookieName: string,
    value: string,
    cookieOptions?: {
      maxAge?: number;
      expires?: Date;
    }
  ): void {
    if (typeof document === "undefined") {
      return;
    }

    let cookieString = `${cookieName}=${encodeURIComponent(value)}`;

    if (cookieOptions?.maxAge) {
      cookieString += `; max-age=${cookieOptions.maxAge}`;
    } else if (cookieOptions?.expires) {
      cookieString += `; expires=${cookieOptions.expires.toUTCString()}`;
    }

    cookieString += `; path=${path}`;

    if (domain) {
      cookieString += `; domain=${domain}`;
    }

    if (secure) {
      cookieString += "; secure";
    }

    cookieString += `; samesite=${sameSite}`;

    document.cookie = cookieString;
  }

  /**
   * Remove a cookie
   */
  function removeCookie(cookieName: string): void {
    if (typeof document === "undefined") {
      return;
    }

    let cookieString = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=${path}`;

    if (domain) {
      cookieString += `; domain=${domain}`;
    }

    document.cookie = cookieString;
  }

  return {
    getItem: (key: string): string | null => {
      try {
        const value = getCookie(key);
        return value;
      } catch (error) {
        console.warn("Failed to get cookie:", error);
        return null;
      }
    },

    setItem: (key: string, value: string): void => {
      try {
        // Try to parse the value as JSON to extract session expiration
        let maxAge: number | undefined = options.maxAge;

        try {
          const parsed = JSON.parse(value);
          // If the stored value contains a session with expires_at, calculate maxAge
          if (parsed?.session?.expires_at) {
            const expiresAt = parsed.session.expires_at;
            const now = Math.floor(Date.now() / 1000);
            const remainingSeconds = expiresAt - now;
            // Only set maxAge if it's positive (not expired)
            if (remainingSeconds > 0) {
              maxAge = remainingSeconds;
            }
          }
        } catch {
          // If parsing fails, value is not JSON, use default maxAge if provided
        }

        setCookie(key, value, maxAge ? { maxAge } : undefined);
      } catch (error) {
        console.warn("Failed to set cookie:", error);
      }
    },

    removeItem: (key: string): void => {
      try {
        removeCookie(key);
      } catch (error) {
        console.warn("Failed to remove cookie:", error);
      }
    },
  };
}
