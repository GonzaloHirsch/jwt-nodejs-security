import { CustomError } from './customError';

export class ValidationError extends CustomError {
    constructor(message: string) {
        super(message, 400);
    }
}
