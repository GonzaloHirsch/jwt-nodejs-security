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
