import express from 'express';
import { json } from 'body-parser';
import routes from './routes/index';

// Middleware
import { errorHandler } from './middleware/errorHandler';
import config from './config';

const app = express();
app.use(json());

// Add the routes with the base prefix
app.use('/' + config.prefix, routes);

// Add error handling
app.use(errorHandler);

// Listen only if DB connection works
app.listen(config.port, () => {
    console.log(`server is listening on port ${config.port}`);
});
