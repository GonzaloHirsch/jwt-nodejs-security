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
