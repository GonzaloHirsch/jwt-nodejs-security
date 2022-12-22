// We'll use Express to route incoming requests to handlers.
import { Router } from 'express';
// Add the auth routes and make them available to our API.
import auth from './auth';
// Add the user routes and make them available to our API.
import user from './user';

const routes = Router();

routes.use('/auth', auth);
// All user operations will be available under the "users" route prefix.
routes.use('/users', user);

// Allow our router to be used outside of this file.
export default routes;
