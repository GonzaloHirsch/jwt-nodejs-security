import bcrypt from 'bcrypt';
import { NotFoundError } from '../exceptions/notFoundError';
import { ValidationError } from '../exceptions/validationError';

export interface IUser {
    id: string;
    username: string;
    // Password is marked as optional in order to be able to return it without it
    // We still verify it's not empty when creating a user
    password?: string;
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
        password: '$2b$12$ov6s318JKzBIkMdSMvHKdeTMHSYMqYxCI86xSHL9Q1gyUpwd66Q2e', // testuser1_password
        role: Roles.USER
    },
    '1': {
        id: '1',
        username: 'testuser2',
        password: '$2b$12$63l0Br1wIniFBFUnHaoeW.55yh8.a3QcpCy7hYt9sfaIDg.rnTAPC', // testuser2_password
        role: Roles.USER
    },
    '2': {
        id: '2',
        username: 'testuser3',
        password: '$2b$12$fTu/nKtkTsNO91tM7wd5yO6LyY1HpyMlmVUE9SM97IBg8eLMqw4mu', // testuser3_password
        role: Roles.USER
    },
    '3': {
        id: '3',
        username: 'testadmin1',
        password: '$2b$12$tuzkBzJWCEqN1DemuFjRuuEs4z3z2a3S5K0fRukob/E959dPYLE3i', // testadmin1_password
        role: Roles.ADMIN
    },
    '4': {
        id: '4',
        username: 'testadmin2',
        password: '$2b$12$.dN3BgEeR0YdWMFv4z0pZOXOWfQUijnncXGz.3YOycHSAECzXQLdq', // testadmin2_password
        role: Roles.ADMIN
    }
};
let nextUserId = Object.keys(users).length;

const generateSafeCopy = (user : IUser) : IUser => {
    let _user = { ...user };
    delete _user.password;
    return _user;
}

export const getUser = (id: string): IUser => {
    if (!(id in users)) throw new NotFoundError(`User with ID ${id} not found`);
    return generateSafeCopy(users[id]);
};

export const getUserByUsername = (username: string): IUser | undefined => {
    const possibleUsers = Object.values(users).filter((user) => user.username === username);
    // Undefined if no user with that username
    if (possibleUsers.length == 0) return undefined;
    return generateSafeCopy(possibleUsers[0]);
};

export const getAllUsers = (restrictedView: boolean): IUser[] => {
    return Object.values(users)
        .filter((user) => (restrictedView && user.role === Roles.USER) || !restrictedView)
        .map((elem) => generateSafeCopy(elem));
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
    // Create the user
    users[id] = {
        username,
        password: await bcrypt.hash(password, 12),
        role,
        id
    };
    return generateSafeCopy(users[id]);
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
    // todo: Add checks according to use case
    if (password.length === 0) throw new ValidationError('Invalid password');

    // Store encrypted password
    users[id].password = await bcrypt.hash(password, 12);
};
