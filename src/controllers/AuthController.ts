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
