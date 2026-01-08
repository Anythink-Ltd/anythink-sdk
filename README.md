# @anythink-cloud/sdk

React SDK for the Anythink platform

## Installation

```bash
npm install @anythink-cloud/sdk
# or
yarn add @anythink-cloud/sdk
# or
pnpm add @anythink-cloud/sdk
```

## Usage

To initialise the auth client:

```typescript
import { AuthClient } from "@anythink-cloud/sdk";

let authClientInstance: AuthClient | null = null;

export const getAuthClient = (): AuthClient => {
  if (!authClientInstance) {
    authClientInstance = new AuthClient({
      instanceUrl: "<your_anythink_instance_url>",
      orgId: 12345678, // <your_anythink_org_id>
      cookieStorage: {
        name: "anythink_auth_session", // use a unique identifier here
      },
    });
  }
  return authClientInstance;
};
```

To use the auth provider:

```typescript

const onSignOut = () => { ... }

// ....

<AuthProvider
    authClient={getAuthClient()}
    callbacks={{ onSignOut }}
    loginUrl="/auth/login" // replace with your login url
    authPrefix="/auth" // replace with your auth page prefix
>
    {children}
</AuthProvider>
```

To use the base service:

```typescript
class MyService extends AuthenticatedBaseService {
  constructor() {
    super(getAuthClient(), "<your_anythink_instance_url>");
  }
}
```

Login example:

```typescript
import { useAuth } from "@anythink-cloud/sdk";

const auth = useAuth();
const [error, setError] = useState("");

// ....

const handleLoginSubmit = async (values: {
  email: string;
  password: string;
}) => {
  try {
    setError(null);
    await auth?.signIn(values.email, values.password);
  } catch (err: unknown) {
    setError(err?.toString() ?? "An error occurred. Please try again.");
  }
};
```

## Development

```bash
# Install dependencies
yarn install

# Build the package
yarn build

# Watch mode for development
yarn dev

# Type checking
yarn typecheck

# Linting
yarn lint

# Run tests
yarn test

# Run tests in watch mode
yarn test:watch

# Run tests with coverage
yarn test:coverage
```

## Testing

The SDK uses [Vitest](https://vitest.dev/) for testing. Tests are being added bit by bit as this is built out.

## License

MIT
