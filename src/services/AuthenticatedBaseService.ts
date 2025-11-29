import axios, {
  AxiosError,
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
} from "axios";
import { AuthClient } from "@/auth/client";

/**
 * Base service class with automatic token injection and refresh handling
 */
export class AuthenticatedBaseService {
  public client: AxiosInstance;
  private authClient: AuthClient;
  private instanceUrl: string;

  constructor(authClient: AuthClient, instanceUrl: string) {
    this.authClient = authClient;
    this.instanceUrl = instanceUrl;

    this.client = axios.create({
      baseURL: this.instanceUrl,
    });

    this.setupInterceptors();
  }

  /**
   * Setup request and response interceptors
   */
  private setupInterceptors(): void {
    // Request interceptor: Inject access token
    this.client.interceptors.request.use(
      (config) => {
        const token = this.authClient.getAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor: Handle token refresh on 401
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & {
          _retry?: boolean;
        };

        // If the error is 401 (Unauthorized) and we haven't already tried to refresh
        if (
          error.response?.status === 401 &&
          originalRequest &&
          !originalRequest._retry
        ) {
          originalRequest._retry = true;

          try {
            // Try to refresh the token
            const { data, error: refreshError } =
              await this.authClient.refreshSession();

            if (data.session && !refreshError) {
              // Retry the original request with the new token
              const token = this.authClient.getAccessToken();
              if (token) {
                if (!originalRequest.headers) {
                  originalRequest.headers = {};
                }
                originalRequest.headers.Authorization = `Bearer ${token}`;
              }
              return this.client(originalRequest);
            } else {
              // Refresh failed, sign out
              await this.authClient.signOut();
            }
          } catch (refreshError) {
            // Refresh failed, sign out
            await this.authClient.signOut();
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  /**
   * GET request
   */
  protected async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.client.get(url, config);
    return response.data;
  }

  /**
   * POST request
   */
  protected async post<TRequest, TResponse>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig
  ): Promise<TResponse> {
    const response: AxiosResponse<TResponse> = await this.client.post(
      url,
      data,
      config
    );
    return response.data;
  }

  /**
   * POST request with form data
   */
  protected async postFormData<FormData, TResponse>(
    url: string,
    data: FormData
  ): Promise<TResponse> {
    const response: AxiosResponse<TResponse> = await this.client.post(
      url,
      data,
      {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      }
    );
    return response.data;
  }

  /**
   * PUT request
   */
  protected async put<TRequest, TResponse>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig
  ): Promise<TResponse> {
    const response: AxiosResponse<TResponse> = await this.client.put(
      url,
      data,
      config
    );
    return response.data;
  }

  /**
   * PATCH request
   */
  protected async patch<TRequest, TResponse>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig
  ): Promise<TResponse> {
    const response: AxiosResponse<TResponse> = await this.client.patch(
      url,
      data,
      config
    );
    return response.data;
  }

  /**
   * DELETE request
   */
  protected async delete<T = void>(
    url: string,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const response: AxiosResponse<T> = await this.client.delete(url, config);
    return response.data;
  }

  /**
   * Get the underlying Axios instance (for advanced usage)
   */
  getClient(): AxiosInstance {
    return this.client;
  }
}
