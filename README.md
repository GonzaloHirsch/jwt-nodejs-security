# Hacking JWT - Toptal

Sample Express REST API with JWT authentication/authorization.

Endpoints once the project is finished:
-   `/PREFIX/users GET`: Get all users (`PROTECTED`)
-   `/PREFIX/users POST`: Create a new user
-   `/PREFIX/users/{ID} DELETE`: Delete a specific user (`PROTECTED`)
-   `/PREFIX/users/{ID} PATCH`: Update a specific user (`PROTECTED`)
-   `/PREFIX/users/{ID} GET`: Get a specific user (`PROTECTED`)
-   `/PREFIX/auth/login POST`: Log in a user
-   `/PREFIX/auth/change-password POST`: Changes password for a user (`PROTECTED`)

Endpoints marked as `PROTECTED` require an `Authorization: Bearer <TOKEN>` header.

## Basic Project

### Creating the Project

Starting with an empty folder, initialize the Node project:

```bash
npm init -y
```

The following dependencies will be used:

```bash
npm install typescript ts-node-dev @types/bcrypt @types/express --save-dev
npm install bcrypt body-parser dotenv express
```

A `tsconfig` file is required for TypeScript:

```bash
npx tsc --init
```

### Configuring the Project

Create a new configuration file `src/config/index.ts`. This file will contain all the necessary information coming from the environment:

```typescript
// Add dotenv for environment variables
import * as dotenv from 'dotenv';
dotenv.config();

const config = {
    // JWT important variables
    // Secret is the secret for the signatures
    // Audience and issuer are for validation purposes
    jwt: {
        secret: process.env.JWT_SECRET,
        audience: process.env.JWT_AUDIENCE,
        issuer: process.env.JWT_ISSUER
    },
    // API information such as port and prefix
    port: process.env.PORT || 3000,
    prefix: process.env.API_PREFIX || 'api'
};

export default config;
```

Note that the following environment variables should be set either as environment or a `.env` file:

-   `JWT_SECRET`
-   `JWT_AUDIENCE`
-   `JWT_ISSUER`
-   `PORT`
-   `API_PREFIX`

### Project Storage

Given this is a simple tutorial, we'll avoid having a fully-fledged database, so we'll store the data locally in the server state. For this we have a file `src/state/users.ts` which has all the logic for storing and querying our users (the CRUD):

```typescript
import bcrypt from 'bcrypt';
import { NotFoundError } from '../exceptions/notFoundError';
import { ValidationError } from '../exceptions/validationError';

export interface IUser {
    id: string;
    username: string;
    password: string;
    role: Roles;
}

export enum Roles {
    ADMIN = 'ADMIN',
    USER = 'USER'
}

let users: { [id: string]: IUser } = {
    '0': {
        id: '0',
        username: 'testuser1',
        password: '$2b$12$ov6s318JKzBIkMdSMvHKdeTMHSYMqYxCI86xSHL9Q1gyUpwd66Q2e',   
        // testuser1_password
        role: Roles.USER
    },
    '1': {
        id: '1',
        username: 'testuser2',
        password: '$2b$12$63l0Br1wIniFBFUnHaoeW.55yh8.a3QcpCy7hYt9sfaIDg.rnTAPC',   
        // testuser2_password
        role: Roles.USER
    },
    '2': {
        id: '2',
        username: 'testuser3',
        password: '$2b$12$fTu/nKtkTsNO91tM7wd5yO6LyY1HpyMlmVUE9SM97IBg8eLMqw4mu',   
        // testuser3_password
        role: Roles.USER
    },
    '3': {
        id: '3',
        username: 'testadmin1',
        password: '$2b$12$tuzkBzJWCEqN1DemuFjRuuEs4z3z2a3S5K0fRukob/E959dPYLE3i',   
        // testadmin1_password
        role: Roles.ADMIN
    },
    '4': {
        id: '4',
        username: 'testadmin2',
        password: '$2b$12$.dN3BgEeR0YdWMFv4z0pZOXOWfQUijnncXGz.3YOycHSAECzXQLdq',   
        // testadmin2_password
        role: Roles.ADMIN
    },
};
let nextUserId = Object.keys(users).length;

export const getUser = (id: string): IUser => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    return users[id];
};

export const getUserByUsername = (username: string): IUser | undefined => {
    const possibleUsers = Object.values(users).filter((user) => user.username === username);
    return possibleUsers.length > 0 ? possibleUsers[0] : undefined;
};

export const getAllUsers = (restrictedView: boolean): IUser[] => {
    return Object.values(users).filter((user) => (restrictedView && user.role === Roles.USER) || !restrictedView);
};

export const createUser = async (username: string, password: string, role: Roles): Promise<IUser> => {
    username = username.trim();
    password = password.trim();

    // todo: Add checks according to use case
    if (username.length === 0) throw new ValidationError('Invalid username');
    else if (password.length === 0) throw new ValidationError('Invalid password');
    // Check for duplicates
    if (getUserByUsername(username) != undefined) throw new ValidationError('Username is taken');

    // Generate a user id
    const id: string = nextUserId.toString();
    nextUserId++;
    // todo: hash password
    users[id] = {
        username,
        password: await bcrypt.hash(password, 12),
        role,
        id
    };
    return users[id];
};

export const updateUser = (id: string, username: string, role: Roles): IUser => {
    // Check user exists
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);

    // todo: Add checks according to use case
    if (username.trim().length === 0) throw new ValidationError('Invalid username');
    username = username.trim();
    const userIdWithUsername = getUserByUsername(username)?.id;
    if (userIdWithUsername !== undefined && userIdWithUsername !== id) throw new ValidationError('Username is taken');

    // Apply changes
    users[id].username = username;
    users[id].role = role;

    return users[id];
};

export const deleteUser = (id: string) => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    delete users[id];
};

export const isPasswordCorrect = async (user: IUser, password: string): Promise<boolean> => {
    return await bcrypt.compare(password, user.password);
};

export const changePassword = async (id: string, password: string) => {
    password = password.trim();
    // todo: Add checks according to use case
    if (password.length === 0) throw new ValidationError('Invalid password');

    // Store encrypted password
    users[id].password = await bcrypt.hash(password, 12);
};
```

Note that there are some set users, which have their passwords generated as follows using the `Node` CLI:

```javascript
await require('bcrypt').hash('PASSWORD_TO_HASH', 12)
```

There might be some exceptions, such as the following ones, which we'll create in the upcoming sections:

```typescript
import { NotFoundError } from '../exceptions/notFoundError';
import { ValidationError } from '../exceptions/validationError';
```

### Project Entrypoint

Create a new file `src/index.ts` with the entrypoint of the API:

```typescript
import express from 'express';
import { json } from 'body-parser';

// Middleware
import config from './config';

const app = express();
app.use(json());

// Listen only if DB connection works
app.listen(config.port, () => {
    console.log(`server is listening on port ${config.port}`);
});
```

Update the `package.json` file to include the following configuration:

```json
"main": "index.js",
"scripts": {
    "start": "ts-node-dev src/index.ts"
},
```

### Error Handling

In order to use asynchronous handlers and have proper error handling, given Express doesn't catch the promise rejections, we need some wrapper code for this.

We create a new file `src/middleware/asyncHandler.ts` with the following content. This handler is meant to wrap function handlers and propagate promise errors into the error handler we'll add next.

```typescript
import { NextFunction, Request, Response } from 'express';

/**
 * Async handler to wrap the API routes, this allows for async error handling.
 * @param fn Function to call for the API endpoint
 * @returns Promise with a catch statement
 */
export const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => void) => (req: Request, res: Response, next: NextFunction) => {
    return Promise.resolve(fn(req, res, next)).catch(next);
};
```

Now that we have an async handler in place, we can create the error handler file `src/middleware/errorHandler.ts`. For this handler we use custom exceptions to properly define errors in our code. We'll define the custom error next.

```typescript
import { Request, Response, NextFunction } from 'express';
import { CustomError, IResponseError } from '../exceptions/customError';

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
    console.error(err);
    if (!(err instanceof CustomError)) {
        res.status(500).send(
            JSON.stringify({
                message: 'Server error, please try again later'
            })
        );
    } else {
        const customError = err as CustomError;
        let response = {
            message: customError.message
        } as IResponseError;
        // Check if more info to return
        if (customError.additionalInfo) response.additionalInfo = customError.additionalInfo;
        res.status(customError.status).type('json').send(JSON.stringify(response));
    }
}
```

Lastly, we need to create our custom error and custom error response interface in `src/exceptions/customError.ts`. Note that the custom error extends from `Error` and defines an response error interface too.

```typescript
export class CustomError extends Error {
    message!: string;
    status!: number;
    additionalInfo!: any;

    constructor(message: string, status: number = 500, additionalInfo: any = undefined) {
        super(message);
        this.message = message;
        this.status = status;
        this.additionalInfo = additionalInfo;
    }
};

export interface IResponseError {
    message: string;
    additionalInfo?: string;
}
```

With all this set in place, we can add this middleware to our API. Within `src/index.ts` we can add:

```typescript
// ... imports
import { errorHandler } from './middleware/errorHandler';
// ... more imports

// ...

// Add error handling, must be the last middleware to be called
// This will make sure the errors will always be handled properly
app.use(errorHandler);

// Listen only if DB connection works
app.listen(config.port, () => {
    console.log(`server is listening on port ${config.port}`);
});
```

#### Custom Errors

Apart from creating the `CustomError` we'd like to have more granular errors, in order to simplify the API code and have an easier way to unify messages.

We will be creating four other custom errors, but one can add as many as you want. Some of those errors will be mainly used later on when we add authentication and authorization.

-   `src/exceptions/clientError.ts`: Handles status code `400` errors.

    ```typescript
    import { CustomError } from './customError';

    export class ClientError extends CustomError {
        constructor(message: string) {
            super(message, 400);
        }
    }
    ```

-   `src/exceptions/forbiddenError.ts`: Handles status code `403` errors.

    ```typescript
    import { CustomError } from './customError';

    export class ForbiddenError extends CustomError {
        constructor(message: string) {
            super(message, 403);
        }
    }
    ```

-   `src/exceptions/notFoundError.ts`: Handles status code `404` errors.

    ```typescript
    import { CustomError } from './customError';

    export class NotFoundError extends CustomError {
        constructor(message: string) {
            super(message, 404);
        }
    }
    ```

-   `src/exceptions/unauthorizedError.ts`: Handles status code `401` errors.

    ```typescript
    import { CustomError } from './customError';

    export class UnauthorizedError extends CustomError {
        constructor(message: string) {
            super(message, 401);
        }
    }
    ```

-   `src/exceptions/validationError.ts`: Handles status code `400` errors that generate from validations.

    ```typescript
    import { CustomError } from './customError';

    export class ValidationError extends CustomError {
        constructor(message: string) {
            super(message, 400);
        }
    }
    ```

### Routes

The last piece missing of our implementation is the routes. We need the routes to redirect to each of the handlers. For this we create a `src/routes/index.ts` file with the following content:

```typescript
import { Router } from 'express';
import user from './user';

const routes = Router();

routes.use('/users', user);

export default routes;
```

And we need to include these routes in the `src/index.ts` file:

```typescript
// ... imports
import routes from './routes/index';
// ... more imports
const app = express();
app.use(json());

// Add the routes with the base prefix
// Must come before the error handler
app.use('/' + config.prefix, routes);

app.use(errorHandler);

// ...
```

We also need to create a `src/routes/user.ts` file with each of the `/users` route prefix. These routes make use of the `asyncHandler` we created earlier.

```typescript
import { Router } from 'express';
import UserController from '../controllers/UserController';

// Middleware
import { asyncHandler } from '../middleware/asyncHandler';

const router = Router();

// Get all users
router.get('/', [], asyncHandler(UserController.listAll));

// Get one user
router.get('/:id([0-9a-z]{24})', [], asyncHandler(UserController.getOneById));

// Create a new user
router.post('/', [], asyncHandler(UserController.newUser));

// Edit one user
router.patch('/:id([0-9a-z]{24})', [], asyncHandler(UserController.editUser));

// Delete one user
router.delete('/:id([0-9a-z]{24})', [], asyncHandler(UserController.deleteUser));

export default router;
```

One of the last things to configure is the `src/controllers/UserController.ts`, which contains the logic for our user endpoints:

```typescript
import { NextFunction, Request, Response } from 'express';
import { getAllUsers, Roles, getUser, createUser, updateUser, deleteUser } from '../state/users';

class UserController {
    static listAll = async (req: Request, res: Response, next: NextFunction) => {
        // Execute the query
        // No limits to the types of users it returns
        const users = getAllUsers(false);

        // Send the users object
        res.status(200).type('json').send(users);
    };

    static getOneById = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id: string = req.params.id;

        // Get the usser
        const user = getUser(id);

        res.status(200).type('json').send(user);
    };

    static newUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get parameters from the body
        let { username, password } = req.body;
        const user = await createUser(username, password, Roles.USER);

        // If all ok, send 201 response
        res.status(201).type('json').send(user);
    };

    static editUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id = req.params.id;

        // Get values from the body
        const { username, role } = req.body;

        const user = getUser(id);
        const updatedUser = updateUser(id, username || user.username, role || user.role);

        res.status(204).type('json').send(updatedUser);
    };

    static deleteUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id = req.params.id;

        deleteUser(id);

        // After all send a 204 (no content, but accepted) response
        res.status(204).type('json').send();
    };
}

export default UserController;
```

Validation errors are handled directly in the state layer we defined earlier.

This configuration exposes the following endpoints:

-   `/PREFIX/users GET`: Get all users
-   `/PREFIX/users POST`: Create a new user
-   `/PREFIX/users/{ID} DELETE`: Delete a specific user
-   `/PREFIX/users/{ID} PATCH`: Update a specific user
-   `/PREFIX/users/{ID} GET`: Get a specific user

## JWT Configuration

Having a basic implementation of the API, we need to implement authentication and authorization to have proper security. For this, we'll have JSON Web Tokens (JWT) for both purposes. The API will emit a JWT when the user logs in and will require it for authorization.

The JWT configuration will require an authorization header with a bearer token:

```
Authorization: Bearer <TOKEN>
```

### JWT Secrets

For this set up we will be using `HS256` as the algorithm for JWT. We need a secret in order to sign the payload. For this we will use the `Node` CLI to generate a secret:

```javascript
require('crypto').randomBytes(128).toString('hex');
```

Using the `crypto` package, we can generate a random string and get it's hexadecimal version. This will be our JWT secret.

**Note**: The secret can be changed at any time. The only effect it will have is basically "logging out" all users. This is because the signatures will be verified with the new secret and won't match.

### Authentication Endpoints

For our basic authentication and authorization we need an endpoint for users to log in and change their password. To achieve this, we create a `src/controllers/AuthController.ts`, which will contain those handlers:

```typescript
import { NextFunction, Request, Response } from 'express';
import { sign } from 'jsonwebtoken';
import { CustomRequest } from '../middleware/checkJwt';
import config from '../config';
import { ClientError } from '../exceptions/clientError';
import { UnauthorizedError } from '../exceptions/unauthorizedError';
import { getUserByUsername, isPasswordCorrect, changePassword } from '../state/users';

class AuthController {
    static login = async (req: Request, res: Response, next: NextFunction) => {
        // Check if username and password are set
        let { username, password } = req.body;
        if (!(username && password)) throw new ClientError('Username and password are required');

        // Get user from database
        const user = getUserByUsername(username);

        // Check if encrypted password match
        if (!user || !(await isPasswordCorrect(user.id, password))) throw new UnauthorizedError("Username and password don't match");

        // Sing JWT, valid for 1 hour
        const token = sign({ userId: user.id, username: user.username, role: user.role }, config.jwt.secret!, {
            expiresIn: '1h',
            notBefore: '0', // Cannot use before now, can be configured to be deferred
            algorithm: 'HS256',
            audience: config.jwt.audience,
            issuer: config.jwt.issuer
        });

        // Send the jwt in the response
        res.type('json').send({ token: token });
    };

    static changePassword = async (req: Request, res: Response, next: NextFunction) => {
        // Get ID from JWT
        const id = (req as CustomRequest).token.payload.userId;

        // Get parameters from the body
        const { oldPassword, newPassword } = req.body;
        if (!(oldPassword && newPassword)) throw new ClientError("Passwords don't match");

        // Check if password is ok
        if (!(await isPasswordCorrect(id, oldPassword))) throw new UnauthorizedError("Old password doesn't match");

        // Call to update the password
        await changePassword(id, newPassword);

        res.status(204).send();
    };
}
export default AuthController;
```

The `login` handler will emit a token if the username and password match. The `changePassword` handler will change a user's password.

To include these handlers in our routes, we need to create a `src/routes/auth.ts` file:

```typescript
import { Router } from 'express';
import AuthController from '../controllers/AuthController';
import { checkJwt } from '../middleware/checkJwt';

// Middleware
import { asyncHandler } from '../middleware/asyncHandler';

const router = Router();
// Login route
router.post('/login', asyncHandler(AuthController.login));

// Change my password
router.post('/change-password', [checkJwt], asyncHandler(AuthController.changePassword));

export default router;
```

And then import this in our `src/routes/index.ts`:

```typescript
import { Router } from 'express';
import auth from './auth';
import user from './user';

const routes = Router();

routes.use('/auth', auth);
routes.use('/users', user);

export default routes;
```

This configuration exposes the following endpoints:

-   `/PREFIX/auth/login POST`: Log in a user
-   `/PREFIX/auth/change-password POST`: Changes password for a user

### Authorization Middleware

We also need a way to verify the tokens and authorize users to access the resources. We use middlewares for this. We will create a middleware that verifies the tokens are correct and other that verifies the user has enough permissions.

The first middleware is `src/middleware/checkJwt.ts`:

```typescript
import { Request, Response, NextFunction } from 'express';
import { verify, JwtPayload } from 'jsonwebtoken';
import config from '../config';

export interface CustomRequest extends Request {
    token: JwtPayload;
}

export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
    // Get the jwt token from the head
    const token = <string>req.headers['authorization'];
    let jwtPayload;

    // Try to validate the token and get data
    try {
        jwtPayload = <any>verify(token?.split(' ')[1], config.jwt.secret!, {
            complete: true,
            audience: config.jwt.audience,
            issuer: config.jwt.issuer,
            algorithms: ['HS256'],
            clockTolerance: 0,
            ignoreExpiration: false,
            ignoreNotBefore: false
        });
        (req as CustomRequest).token = jwtPayload;
    } catch (error) {
        res.status(401)
            .type('json')
            .send(JSON.stringify({ message: 'Missing or invalid token' }));
        return;
    }

    // Call the next middleware or controller
    next();
};
```

Note that the token information is added to the request, which is then forwarded. The error handler won't work here because this middleware occurs before the error handler is included.

Then we create the `src/middleware/checkRole.ts` middleware:

```typescript
import { Request, Response, NextFunction } from 'express';
import { CustomRequest } from './checkJwt';
import { getUser, Roles } from '../state/users';

export const checkRole = (roles: Array<Roles>) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        // Find the user within the database
        const user = getUser((req as CustomRequest).token.payload.userId);

        if (!user) {
            res.status(404)
                .type('json')
                .send(JSON.stringify({ message: 'User not found' }));
            return;
        }

        // Check if array of authorized roles includes the user's role
        if (roles.indexOf(user.role) > -1) next();
        else {
            res.status(403)
                .type('json')
                .send(JSON.stringify({ message: 'Not enough permissions' }));
            return;
        }
    };
};
```

Note that it uses the internal role stored in the database to avoid trusting the JWT in case the user had a change of role in between the token was emitted and now used.

Lastly, we need to update our routes files (`src/routes/auth.ts` and `src/routes/user.ts`) to use these middlewares:

-   `src/routes/auth.ts`

    ```typescript
    import { Router } from 'express';
    import AuthController from '../controllers/AuthController';
    import { checkJwt } from '../middleware/checkJwt';

    // Middleware
    import { asyncHandler } from '../middleware/asyncHandler';

    const router = Router();
    // Login route
    router.post('/login', asyncHandler(AuthController.login));

    // Change my password
    router.post('/change-password', [checkJwt], asyncHandler(AuthController.changePassword));

    export default router;
    ```

-   `src/routes/user.ts`

    ```typescript
    import { Router } from 'express';
    import UserController from '../controllers/UserController';
    import { Roles } from '../state/users';

    // Middleware
    import { asyncHandler } from '../middleware/asyncHandler';
    import { checkJwt } from '../middleware/checkJwt';
    import { checkRole } from '../middleware/checkRole';

    const router = Router();

    // Get all users
    router.get('/', [checkJwt, checkRole([Roles.USER, Roles.ADMIN])], asyncHandler(UserController.listAll));

    // Get one user
    router.get('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.USER, Roles.ADMIN])], asyncHandler(UserController.getOneById));

    // Create a new user
    router.post('/', [], asyncHandler(UserController.newUser));

    // Edit one user
    router.patch('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.USER, Roles.ADMIN])], asyncHandler(UserController.editUser));

    // Delete one user
    router.delete('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.ADMIN])], asyncHandler(UserController.deleteUser));

    export default router;
    ```

In these cases, endpoints that require authentication need to include the `checkJwt` middleware. Authorization is added when the `checkRole` middleware is included and roles with enough permissions are accessed.

### Better Authorization for Handlers

The last thing we need to update are the handlers, so that we add extra validations to have more control on the behavior of our endpoints and the data each user can access and/or modify.

We update the `src/controllers/UserController.ts` file to look like this:

```typescript
import { NextFunction, Request, Response } from 'express';
import { ForbiddenError } from '../exceptions/forbiddenError';
import { CustomRequest } from '../middleware/checkJwt';
import { getAllUsers, Roles, getUser, createUser, updateUser, deleteUser } from '../state/users';

class UserController {
    static listAll = async (req: Request, res: Response, next: NextFunction) => {
        // Execute the query
        // If the user is a USER role, only return other users
        const users = getAllUsers((req as CustomRequest).token.payload.role === Roles.USER);

        // Send the users object
        res.status(200).type('json').send(users);
    };

    static getOneById = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id: string = req.params.id;

        // Validate permissions
        if ((req as CustomRequest).token.payload.role === Roles.USER && req.params.id !== (req as CustomRequest).token.payload.userId) {
            throw new ForbiddenError('Not enough permissions');
        }

        // Get the usser
        const user = getUser(id);

        res.status(200).type('json').send(user);
    };

    static newUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get parameters from the body
        let { username, password } = req.body;
        const user = await createUser(username, password, Roles.USER);

        // If all ok, send 201 response
        res.status(201).type('json').send(user);
    };

    static editUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id = req.params.id;

        // Validate permissions
        if ((req as CustomRequest).token.payload.role === Roles.USER && req.params.id !== (req as CustomRequest).token.payload.userId) {
            throw new ForbiddenError('Not enough permissions');
        }

        // Get values from the body
        const { username, role } = req.body;

        // Verify you cannot make yourself an admin if you are a user
        if ((req as CustomRequest).token.payload.role === Roles.USER && role === Roles.ADMIN) {
            throw new ForbiddenError('Not enough permissions');
        }

        const user = getUser(id);
        const updatedUser = updateUser(id, username || user.username, role || user.role);

        res.status(204).type('json').send(updatedUser);
    };

    static deleteUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the url
        const id = req.params.id;

        deleteUser(id);

        // After all send a 204 (no content, but accepted) response
        res.status(204).type('json').send();
    };
}

export default UserController;
```