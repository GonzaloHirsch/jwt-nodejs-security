# How to Use JWT and Node.js for Better App Security

* * *
This code is published as part of the [corresponding blog article](FINAL-ARTICLE-URL-HERE) at the Toptal Engineering Blog.
For the latest articles on software development, visit <https://www.toptal.com/developers/blog> and subscribe to our newsletter.
* * *

Sample Express REST API with JWT authentication/authorization.

Endpoints once the project is finished:
-   `/API_PREFIX/users GET`: Get all users (`PROTECTED`)
-   `/API_PREFIX/users POST`: Create a new user
-   `/API_PREFIX/users/{ID} DELETE`: Delete a specific user (`PROTECTED`)
-   `/API_PREFIX/users/{ID} PATCH`: Update a specific user (`PROTECTED`)
-   `/API_PREFIX/users/{ID} GET`: Get a specific user (`PROTECTED`)
-   `/API_PREFIX/auth/login POST`: Log in a user
-   `/API_PREFIX/auth/change-password POST`: Changes password for a user (`PROTECTED`)

Endpoints marked as `PROTECTED` require an `Authorization: Bearer <TOKEN>` header.

Note that this **README** contains step-by-step instructions on how to create this project from the ground up. In case you are cloning/forking it, the project is fully functional and works by using the following command:

```bash
npm i && npm start
```

Before running it, it's necessary to configure a .env file. To do so, please refer to [this section](#configure-the-api-environment) of the **README**.

## Create the Node.js API

Create the project folder and initialize the Node.js project:

```bash
mkdir jwt-nodejs-security
cd jwt-nodejs-security
npm init -y
```

Next, add project dependencies and generate a basic `tsconfig` file. This file(which we will not edit during this tutorial) is required for TypeScript:

```bash
npm install typescript ts-node-dev @types/bcrypt @types/express --save-dev
npm install bcrypt body-parser dotenv express
npx tsc --init
```

With the project folder and dependencies in place, we now define our API project.

## Configure the API Environment

The project will use system environment values within our code. To that end, we’ll create a new configuration file, `src/config/index.ts`, that retrieves environment variables from the operating system, making them available to our code:

```typescript
import * as dotenv from 'dotenv';
dotenv.config();

// Create a configuration object to hold those environment variables.
const config = {
    // JWT important variables.
    jwt: {
        // The secret is used to sign and validate signatures.
        secret: process.env.JWT_SECRET,
        // The audience and issuer are used for validation purposes.
        audience: process.env.JWT_AUDIENCE,
        issuer: process.env.JWT_ISSUER
    },
    // The basic API port and prefix configuration values are:
    port: process.env.PORT || 3000,
    prefix: process.env.API_PREFIX || 'api'
};

// Make our confirmation object available to the rest of our code.
export default config;
```

The `dotenv` library allows environment variables to be set in either the operating system or within a `.env` file. We’ll create an `.env` file to define the following values:

- `JWT_SECRET`
- `JWT_AUDIENCE`
- `JWT_ISSUER`
- `PORT`
- `API_PREFIX`

Your `.env` file should look something like the [example](./.env.example) provided in our repository. With the basic API configuration complete, we now move into coding our API's storage.

## Setup In-memory Storage

To avoid the complexities that come with having a fully-fledged database, we’ll store our data locally in the server state. Let's create a TypeScript file, `src/state/users.ts`, to contain the storage and CRUD operations for API user information:

```typescript
import bcrypt from 'bcrypt';
import { NotFoundError } from '../exceptions/notFoundError';
import { ClientError } from '../exceptions/clientError';

// Define the code interface for user objects. 
export interface IUser {
    id: string;
    username: string;
    // The password is marked as optional to allow us to return this structure 
    // without a password value. We'll validate that it is not empty when creating a user.
    password?: string;
    role: Roles;
}

// Our API supports both an admin and regular user, as defined by a role.
export enum Roles {
    ADMIN = 'ADMIN',
    USER = 'USER'
}

// Let's initialize our example API with some user records.
// NOTE: We generate passwords using the Node.js CLI with this command:
// "await require('bcrypt').hash('PASSWORD_TO_HASH', 12)"
let users: { [id: string]: IUser } = {
    '0': {
        id: '0',
        username: 'testuser1',
        // Plaintext password: testuser1_password
        password: '$2b$12$ov6s318JKzBIkMdSMvHKdeTMHSYMqYxCI86xSHL9Q1gyUpwd66Q2e', 
        role: Roles.USER
    },
    '1': {
        id: '1',
        username: 'testuser2',
        // Plaintext password: testuser2_password
        password: '$2b$12$63l0Br1wIniFBFUnHaoeW.55yh8.a3QcpCy7hYt9sfaIDg.rnTAPC', 
        role: Roles.USER
    },
    '2': {
        id: '2',
        username: 'testuser3',
        // Plaintext password: testuser3_password
        password: '$2b$12$fTu/nKtkTsNO91tM7wd5yO6LyY1HpyMlmVUE9SM97IBg8eLMqw4mu',
        role: Roles.USER
    },
    '3': {
        id: '3',
        username: 'testadmin1',
        // Plaintext password: testadmin1_password
        password: '$2b$12$tuzkBzJWCEqN1DemuFjRuuEs4z3z2a3S5K0fRukob/E959dPYLE3i',
        role: Roles.ADMIN
    },
    '4': {
        id: '4',
        username: 'testadmin2',
        // Plaintext password: testadmin2_password
        password: '$2b$12$.dN3BgEeR0YdWMFv4z0pZOXOWfQUijnncXGz.3YOycHSAECzXQLdq',
        role: Roles.ADMIN
    }
};

let nextUserId = Object.keys(users).length;
```

Before we implement specific API routing and handler functions, let's focus on error-handling support for our project. This is an opportunity for us to propagate JWT best practices throughout our project code.

## Add Custom Error Handling

We are using the Express framework for our API. Express does not support proper error handling with asynchronous handlers. Specifically, Express doesn't catch promise rejections from within asynchronous handlers. To catch those rejections, we need to implement an error-handling wrapper function. 

Let's create a new file `src/middleware/asyncHandler.ts` with the following content:

```typescript
import { NextFunction, Request, Response } from 'express';

/**
 * Async handler to wrap the API routes, allowing for async error handling.
 * @param fn Function to call for the API endpoint
 * @returns Promise with a catch statement
 */
export const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => void) => (req: Request, res: Response, next: NextFunction) => {
    return Promise.resolve(fn(req, res, next)).catch(next);
};
```

This handler wraps function handlers and propagates promise errors into an error handler. Before we define the error handler, we'll define some custom exceptions in `src/exceptions/customError.ts`, for use in our application:

```typescript
// Note: Our custom error extends from Error, so we can throw this error as an exception.
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

Now, we create our error handler in the file `src/middleware/errorHandler.ts`:

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
        // Check if there is more info to return.
        if (customError.additionalInfo) response.additionalInfo = customError.additionalInfo;
        res.status(customError.status).type('json').send(JSON.stringify(response));
    }
}
```

With all this error handling in place, we can add this support to our API within the `src/index.ts` file:

```typescript
import { errorHandler } from './middleware/errorHandler';

// Add error handling as the last middleware, just prior to our app.listen call.
// This ensures that all errors are always handled.
app.use(errorHandler);

// app.listen...
```

Although we have implemented general error handling for our API, we want to support throwing rich errors from within our API handlers. Let's define those rich error utility functions now. Each rich error function is defined in their own file, as such:

- `src/exceptions/clientError.ts`: Handles status code 400 errors.

    ```typescript
    import { CustomError } from './customError';

    export class ClientError extends CustomError {
        constructor(message: string) {
            super(message, 400);
        }
    }
    ```

- `src/exceptions/forbiddenError.ts`: Handles status code 403 errors.

    ```typescript
    import { CustomError } from './customError';

    export class ForbiddenError extends CustomError {
        constructor(message: string) {
            super(message, 403);
        }
    }
    ```

- `src/exceptions/notFoundError.ts`: Handles status code 404 errors.

    ```typescript
    import { CustomError } from './customError';

    export class NotFoundError extends CustomError {
        constructor(message: string) {
            super(message, 404);
        }
    }
    ```

- `src/exceptions/unauthorizedError.ts`: Handles status code 401 errors.

    ```typescript
    import { CustomError } from './customError';

    export class UnauthorizedError extends CustomError {
        constructor(message: string) {
            super(message, 401);
        }
    }
    ```

With the basic project and error handling functions implemented, let's define our API endpoints and their handler functions.

## Define our API Endpoints

We're using [Express](https://expressjs.com/) to easily add API support to our application. Let's create a new file `src/index.ts` to define our API's entrypoint:

```typescript
import express from 'express';
import { json } from 'body-parser';
import { errorHandler } from './middleware/errorHandler';
import config from './config';

// Instantiate an Express object.
const app = express();
app.use(json());

// Add error handling as the last middleware, just prior to our app.listen call.
// This ensures that all errors are always handled.
app.use(errorHandler);

// Have our API listen on the configured port.
app.listen(config.port, () => {
    console.log(`server is listening on port ${config.port}`);
});
```

We need to update the npm-generated `package.json` file to add our just-created default application entrypoint. Note we want to place this at the top of the main object's attribute list, as such:

```typescript
{
    "main": "index.js",
    "scripts": {
        "start": "ts-node-dev src/index.ts"
...
```

Next, our API needs its routes defined, and to have those routes redirect to their handlers. Let's create a `src/routes/index.ts` file to link user operation routes into our application. Note: the route specifics and their handler definitions are defined afterwards.

```typescript
import { Router } from 'express';
import user from './user';

const routes = Router();
// All user operations will be available under the "users" route prefix.
routes.use('/users', user);
// Allow our router to be used outside of this file.
export default routes;
```

We need to include these routes in the `src/index.ts` file by importing our route object and then asking our application to use those routes. For reference, the [finished file version](./src/index.ts) may be used to compare with your edited file.

```typescript
import routes from './routes/index';

// Add our route object to the Express object. 
// This must be before the app.listen call.
app.use('/' + config.prefix, routes);

// app.listen... 
```

Now that our API is awaiting the actual user routes and their handler definitions, let's implement those. The user routes must be defined in the `src/routes/user.ts` file and linked to the soon-to-be-defined UserController:

```typescript
import { Router } from 'express';
import UserController from '../controllers/UserController';
import { asyncHandler } from '../middleware/asyncHandler';

const router = Router();

// Note: Each handler is wrapped with our error handling function.
// Get all users.
router.get('/', [], asyncHandler(UserController.listAll));

// Get one user.
router.get('/:id([0-9a-z]{24})', [], asyncHandler(UserController.getOneById));

// Create a new user.
router.post('/', [], asyncHandler(UserController.newUser));

// Edit one user.
router.patch('/:id([0-9a-z]{24})', [], asyncHandler(UserController.editUser));

// Delete one user.
router.delete('/:id([0-9a-z]{24})', [], asyncHandler(UserController.deleteUser));
```

The routes will call handler methods within our `UserController`, but those methods will rely on helper functions to operate on our user information.Let's add those helper functions now before we define the controller. We'll add  these functions at the tailend of our `src/state/users.ts` file:

```typescript
// Place these functions at the end of the file.
// NOTE: Validation errors are handled directly within these functions.

// Generate a copy of the users without their passwords.
const generateSafeCopy = (user : IUser) : IUser => {
    let _user = { ...user };
    delete _user.password;
    return _user;
};

// Recover a user if present.
export const getUser = (id: string): IUser => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    return generateSafeCopy(users[id]);
};

// Recover a user based on username if present, using the username as the query.
export const getUserByUsername = (username: string): IUser | undefined => {
    const possibleUsers = Object.values(users).filter((user) => user.username === username);
    // Undefined if no user exists with that username.
    if (possibleUsers.length == 0) return undefined;
    return generateSafeCopy(possibleUsers[0]);
};

export const getAllUsers = (): IUser[] => {
    return Object.values(users).map((elem) => generateSafeCopy(elem));
};
export const getAllUsers = (restrictedView: boolean): IUser[] => {
    return Object.values(users)
        .filter((user) => (restrictedView && user.role === Roles.USER) || !restrictedView)
        .map((elem) => generateSafeCopy(elem));
};

export const createUser = async (username: string, password: string, role: Roles): Promise<IUser> => {
    username = username.trim();
    password = password.trim();

    // Reader: Add checks according to your custom use case.
    if (username.length === 0) throw new ClientError('Invalid username');
    else if (password.length === 0) throw new ClientError('Invalid password');
    // Check for duplicates.
    if (getUserByUsername(username) != undefined) throw new ClientError('Username is taken');

    // Generate a user id.
    const id: string = nextUserId.toString();
    nextUserId++;
    // Create the user.
    users[id] = {
        username,
        password: await bcrypt.hash(password, 12),
        role,
        id
    };
    return generateSafeCopy(users[id]);
};

export const updateUser = (id: string, username: string, role: Roles): IUser => {
    // Check that user exists.
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);

    // Reader: Add checks according to your custom use case.
    if (username.trim().length === 0) throw new ClientError('Invalid username');
    username = username.trim();
    const userIdWithUsername = getUserByUsername(username)?.id;
    if (userIdWithUsername !== undefined && userIdWithUsername !== id) throw new ClientError('Username is taken');

    // Apply the changes.
    users[id].username = username;
    users[id].role = role;
    return generateSafeCopy(users[id]);
};

export const deleteUser = (id: string) => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    delete users[id];
};

export const isPasswordCorrect = async (id: string, password: string): Promise<boolean> => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    return await bcrypt.compare(password, users[id].password!);
};

export const changePassword = async (id: string, password: string) => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    
    password = password.trim();
    // Reader: Add checks according to your custom use case.
    if (password.length === 0) throw new ClientError('Invalid password');

    // Store encrypted password.
    users[id].password = await bcrypt.hash(password, 12);
};
```

The final part of our route handling requires the creation of our `UserController`. Create the `src/controllers/UserController.ts` file:

```typescript
import { NextFunction, Request, Response } from 'express';
import { getAllUsers, Roles, getUser, createUser, updateUser, deleteUser } from '../state/users';

class UserController {
    static listAll = async (req: Request, res: Response, next: NextFunction) => {
        // Retrieve all users.
        const users = getAllUsers(false);
        // Return the user information.
        res.status(200).type('json').send(users);
    };

    static getOneById = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the URL.
        const id: string = req.params.id;

        // Get the user with the requested ID.
        const user = getUser(id);

        // NOTE: We will only get here if we found a user with the requested ID.
        res.status(200).type('json').send(user);
    };

    static newUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the username and password.
        let { username, password } = req.body;
        // We can only create regular users through this function.
        const user = await createUser(username, password, Roles.USER);

        // NOTE: We will only get here if all new user information 
        // is valid and the user was created.
        // Send an HTTP "Created" response.
        res.status(201).type('json').send(user);
    };

    static editUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the user ID.
        const id = req.params.id;

        // Get values from the body.
        const { username, role } = req.body;

        if (!Object.values(Roles).includes(role))
            throw new ClientError('Invalid role');

        // Retrieve and update the user record.
        const user = getUser(id);
        const updatedUser = updateUser(id, username || user.username, role || user.role);

        // NOTE: We will only get here if all new user information 
        // is valid and the user was updated.
        // Send an HTTP "No Content" response.
        res.status(204).type('json').send(updatedUser);
    };

    static deleteUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the URL.
        const id = req.params.id;

        deleteUser(id);

        // NOTE: We will only get here if we found a user with the requested ID and    
        // deleted it.
        // Send an HTTP "No Content" response.
        res.status(204).type('json').send();
    };
}

export default UserController;
```

This configuration exposes the following endpoints:

`/API_PREFIX/users GET`: Get all users
`/API_PREFIX/users POST`: Create a new user
`/API_PREFIX/users/{ID} DELETE`: Delete a specific user
`/API_PREFIX/users/{ID} PATCH`: Update a specific user
`/API_PREFIX/users/{ID} GET`: Get a specific user

At this point, our API routes and their handlers are implemented. We are ready to add JWT support to our API.

## Add and Configure JWT

We now have a basic API implementation complete, but we need to implement authentication and authorization to keep it secure. We'll use JSON Web Tokens (JWT) for both purposes. The API will emit a JWT when the user authenticates and will require our generated token for each API call to verify those calls are authorized.

For each client call, an authorization header with bearer token passes our generated JWT to the API:

```bash
Authorization: Bearer <TOKEN>
```

We need to install some dependencies into our project to support JWT:

```bash
npm install @types/jsonwebtoken --save-dev
npm install jsonwebtoken
```

For this set up we will be using HS256 as the algorithm for JWT, which is a shared secret algorithm. Therefore, we need a generate that secret to sign and validate each payload. For this we'll use the Node CLI to generate our JWT secret, by using the `crypto` package to generate a random hexadecimal string.

```typescript
require('crypto').randomBytes(128).toString('hex');
```

**Note**: The secret can be changed at any time, but each change will force all users to effectively log out because their authentication tokens become invalid.

## Create the JWT Authentication Controller

Our API's authentication and authorization functionality requires user endpoints to log in and potentially change their password. To achieve this, we create `src/controllers/AuthController.ts` to contain those handlers:

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
        // Ensure the username and password are provided.
        // Throw an exception back to the client if those values are missing.
        let { username, password } = req.body;
        if (!(username && password)) throw new ClientError('Username and password are required');

        const user = getUserByUsername(username);

        // Check if the provided password matches our encrypted password.
        if (!user || !(await isPasswordCorrect(user.id, password))) throw new UnauthorizedError("Username and password don't match");

        // Generate and sign a JWT that is valid for one hour.
        const token = sign({ userId: user.id, username: user.username, role: user.role }, config.jwt.secret!, {
            expiresIn: '1h',
            notBefore: '0', // Cannot use before now, can be configured to be deferred.
            algorithm: 'HS256',
            audience: config.jwt.audience,
            issuer: config.jwt.issuer
        });

        // Return the JWT in our response.
        res.type('json').send({ token: token });
    };

    static changePassword = async (req: Request, res: Response, next: NextFunction) => {
        // Retrieve the user ID from the incoming JWT.
        const id = (req as CustomRequest).token.payload.userId;

        // Get the provided parameters from the request body.
        const { oldPassword, newPassword } = req.body;
        if (!(oldPassword && newPassword)) throw new ClientError("Passwords don't match");

        // Check if old password matches our currently stored password, then we proceed.
        // Throw an error back to the client if the old password is mismatched.
        if (!(await isPasswordCorrect(id, oldPassword))) throw new UnauthorizedError("Old password doesn't match");

        // Update the user password.
        // Note: We will not hit this code if the old password compare failed.
        await changePassword(id, newPassword);

        res.status(204).send();
    };
}
export default AuthController;
```

Our authentication controller contains two handlers for: login verification and user password changes.  With the authentication controller implemented, now we move to creating authorization hooks to provide generalized authentication and authorization code for all API routes in our project.

## Implement Authorization Hooks

We want each of our API endpoints to be secure. We can add this security by creating a common JWT validation and role authentication hook that we can add to each of our handlers. We will implement these hooks into middleware.

We'll write the first middleware to validate incoming JWT tokens in the `src/middleware/checkJwt.ts` file:

```typescript
import { Request, Response, NextFunction } from 'express';
import { verify, JwtPayload } from 'jsonwebtoken';
import config from '../config';

// The CustomRequest interface allows providing JWTs to our controllers.
export interface CustomRequest extends Request {
    token: JwtPayload;
}

export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
    // Get the JWT from the request header.
    const token = <string>req.headers['authorization'];
    let jwtPayload;

    // Validate the token and retrieve its data.
    try {
        // Verify the payload fields.
        jwtPayload = <any>verify(token?.split(' ')[1], config.jwt.secret!, {
            complete: true,
            audience: config.jwt.audience,
            issuer: config.jwt.issuer,
            algorithms: ['HS256'],
            clockTolerance: 0,
            ignoreExpiration: false,
            ignoreNotBefore: false
        });
        // Add the payload to the request so controllers may access it.
        (req as CustomRequest).token = jwtPayload;
    } catch (error) {
        res.status(401)
            .type('json')
            .send(JSON.stringify({ message: 'Missing or invalid token' }));
        return;
    }

    // Pass programmatic flow to the next middleware/controller.
    next();
};
```

Two important notes: token information is added to the request, which is then forwarded, and the error handler isn't available at this point because this middleware occurs before the error handler is included in our Express pipeline.

Next, we create a JWT authorization `src/middleware/checkRole.ts`:

```typescript
import { Request, Response, NextFunction } from 'express';
import { CustomRequest } from './checkJwt';
import { getUser, Roles } from '../state/users';

export const checkRole = (roles: Array<Roles>) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        // Find the user with the requested ID.
        const user = getUser((req as CustomRequest).token.payload.userId);

        // Ensure we found a user.
        if (!user) {
            res.status(404)
                .type('json')
                .send(JSON.stringify({ message: 'User not found' }));
            return;
        }

        // Ensure the user's role is contained in the authorized roles.
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

Note that we the user's server set role instead of the one contained in the JWT. This allows a previously authenticated user to have their permissions changed midstream and the user never gets free access to a route even if their authorization JWT originally allowed it.

Now we need to update our routes files. Create the `src/routes/auth.ts` for our authorization middleware:

```typescript
import { Router } from 'express';
import AuthController from '../controllers/AuthController';
import { checkJwt } from '../middleware/checkJwt';
import { asyncHandler } from '../middleware/asyncHandler';

const router = Router();
// Attach our authentication route.
router.post('/login', asyncHandler(AuthController.login));

// Attach our change password route. Note that checkJwt enforces endpoint authorization.
router.post('/change-password', [checkJwt], asyncHandler(AuthController.changePassword));

export default router;
```

Now we completely replace the contents of our user routes file, `src/routes/user.ts`, to add in authorization and required roles for each endpoint:

```typescript
import { Router } from 'express';
import UserController from '../controllers/UserController';
import { Roles } from '../state/users';
import { asyncHandler } from '../middleware/asyncHandler';
import { checkJwt } from '../middleware/checkJwt';
import { checkRole } from '../middleware/checkRole';

const router = Router();

// Define our routes and their required authorization roles.
// Get all users.
router.get('/', [checkJwt, checkRole([Roles.ADMIN])], asyncHandler(UserController.listAll));

// Get one user.
router.get('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.USER, Roles.ADMIN])], asyncHandler(UserController.getOneById));

// Create a new user.
router.post('/', asyncHandler(UserController.newUser));

// Edit one user.
router.patch('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.USER, Roles.ADMIN])], asyncHandler(UserController.editUser));

// Delete one user.
router.delete('/:id([0-9]{1,24})', [checkJwt, checkRole([Roles.ADMIN])], asyncHandler(UserController.deleteUser));

export default router;
```

Each endpoint validates the incoming JWT with `checkJwt` and then authorizes the user roles with the `checkRole` middleware. 

To finish integrating the authentication routes, we need to attach our authentication and user routes to our API's route list in the `src/routes/index.ts` file (this is a complete file listing):

```typescript
import { Router } from 'express';
import user from './user';

const routes = Router();
// All auth operations will be available under the "auth" route prefix.
routes.use('/auth', auth);
// All user operations will be available under the "users" route prefix.
routes.use('/users', user);
// Allow our router to be used outside of this file.
export default routes;
```

This configuration now exposes the additional endpoints:

- `/API_PREFIX/auth/login POST`: Log in a user
- `/API_PREFIX/auth/change-password POST`: Changes password for a user

With our authentication and authorization middleware in place, and the JWT payload available in each request, we can now make our endpoint handlers more robust with better business logic to ensure users only have access to the allowed functionality.

Integrate JWT Authorization into Endpoints

We'll add extra validations to our endpoints' implementation to define the data each user can access and/or modify.

We update the `src/controllers/UserController.ts` file with this in mind:

```typescript
import { NextFunction, Request, Response } from 'express';
import { getAllUsers, Roles, getUser, createUser, updateUser, deleteUser } from '../state/users';
import { ForbiddenError } from '../exceptions/forbiddenError';
import { ClientError } from '../exceptions/clientError';
import { CustomRequest } from '../middleware/checkJwt';

class UserController {
    static listAll = async (req: Request, res: Response, next: NextFunction) => {
        // Retrieve all users.
        const users = getAllUsers();
        // Return the user information.
        res.status(200).type('json').send(users);
    };

    static getOneById = async (req: Request, res: Response, next: NextFunction) => {
        // Get the ID from the URL.
        const id: string = req.params.id;

        // New code: Restrict USER requestors to retrieve their own record.
        // Allow ADMIN requestors to retrieve any record.
        if ((req as CustomRequest).token.payload.role === Roles.USER && req.params.id !== (req as CustomRequest).token.payload.userId) {
            throw new ForbiddenError('Not enough permissions');
        }

        // Get the user with the requested ID.
        const user = getUser(id);

        // NOTE: We will only get here if we found a user with the requested ID.
        res.status(200).type('json').send(user);
    };

    static newUser = async (req: Request, res: Response, next: NextFunction) => {
        // NOTE: No change to this function.
        // Get the user name and password.
        let { username, password } = req.body;
        // We can only create regular users through this function.
        const user = await createUser(username, password, Roles.USER);

        // NOTE: We will only get here if all new user information 
        // is valid and the user was created.
        // Send an HTTP "Created" response.
        res.status(201).type('json').send(user);
    };

    static editUser = async (req: Request, res: Response, next: NextFunction) => {
        // Get the user ID.
        const id = req.params.id;

        // New code: Restrict USER requestors to edit their own record.
        // Allow ADMIN requestors to edit any record.
        if ((req as CustomRequest).token.payload.role === Roles.USER && req.params.id !== (req as CustomRequest).token.payload.userId) {
            throw new ForbiddenError('Not enough permissions');
        }

        // Get values from the body.
        const { username, role } = req.body;

        // New code: Do not allow USERs to change themselves to an ADMIN.
        // Verify you cannot make yourself an ADMIN if you are a USER.
        if ((req as CustomRequest).token.payload.role === Roles.USER && role === Roles.ADMIN) {
            throw new ForbiddenError('Not enough permissions');
        }
        // Verify the role is correct.
        else if (!Object.values(Roles).includes(role)) 
             throw new ClientError('Invalid role');

        // Retrieve and update the user record.
        const user = getUser(id);
        const updatedUser = updateUser(id, username || user.username, role || user.role);

        // NOTE: We will only get here if all new user information
        // is valid and the user was updated.
        // Send an HTTP "No Content" response.
        res.status(204).type('json').send(updatedUser);
    };

    static deleteUser = async (req: Request, res: Response, next: NextFunction) => {
        // NOTE: No change to this function.
        // Get the ID from the URL.
        const id = req.params.id;

        deleteUser(id);

        // NOTE: We will only get here if we found a user with the requested ID and    
        // deleted it.
        // Send an HTTP "No Content" response.
        res.status(204).type('json').send();
    };
}

export default UserController;
```

Our API is now complete and secure. Let's test it.

## JWT and Node.js Testing

In order to test our API, it needs to be running. Start our project up.

```bash
npm run start
```

We'll use [Postman](https://www.postman.com/downloads/) to test our API. Please ensure it is installed.

Within Postman, we need to create two requests: one for authenticating a user, and another to use the returned JWT to make a call against one of our API's endpoints. Let's create the authentication request:

1. Create a new POST request for user authentication.
2. Name this request "JWT Node.js Authentication". 
3. Set the request's address to `localhost:3000/api/auth/login`.
4. Set the body type to raw and `JSON`.
5. Update the body to contain this JSON value:
    ```json
    {
        "username": "testadmin1testuser1",
        "password": "testadmin1_passwordtestuser1_password"
    }
    ```
6. Run the request in Postman.
7. Save the return JWT information for our next call.

Now that we have a JWT for our test user, we'll create another request to test one of our endpoints to get the available USER records:

1. Create a new GET request for user authentication.
2. Name this request "JWT Node.js Get Users". 
3. Set the request's address to `localhost:3000/api/users`.
4. On the request's authorization tab, set the type to "Bearer Token".
5. Copy the return JWT from our previous request into the "Token" field on this tab.
6. Run the request in Postman.
7. View the user list returned by our API.

Obviously, this is just one test of our API, but the same pattern may be followed to fully explore the API calls and test our authorization logic.

To easily test the API, we provide a Postman collection with example requests that anyone can try.

[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/17051991-d520f5b0-748b-4bf9-b506-6ab1daf542c7?action=collection%2Ffork&collection-url=entityId%3D17051991-d520f5b0-748b-4bf9-b506-6ab1daf542c7%26entityType%3Dcollection%26workspaceId%3D1ff03695-0923-4c9c-a217-2fd2f17f0c11)