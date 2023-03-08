import { Request, Response, NextFunction } from 'express';
import { CustomRequest } from './checkJwt';
import { getUser, Roles } from '../state/users';

export const checkRole = (roles: Array<Roles>) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        // Find the user within the database.
        const user = getUser((req as CustomRequest).token.payload.userId);

        if (!user) {
            res.status(404)
                .type('json')
                .send(JSON.stringify({ message: 'User not found' }));
            return;
        }

        // Check if array of authorized roles includes the user's role.
        if (roles.indexOf(user.role) > -1) next();
        else {
            res.status(403)
                .type('json')
                .send(JSON.stringify({ message: 'Not enough permissions' }));
            return;
        }
    };
};
