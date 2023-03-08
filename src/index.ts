import express from 'express';
import { json } from 'body-parser';
import routes from './routes/index';
import { errorHandler } from './middleware/errorHandler';
import config from './config';

// Instantiate an Express object.
const app = express();
app.use(json());

// Add our route object to the Express object. 
// This must be before the app.listen call.
app.use('/' + config.prefix, routes);

// Add error handling as the last middleware, just prior to our app.listen call.
// This ensures that all errors are always handled.
app.use(errorHandler);

// Have our API listen on the configured port.
app.listen(config.port, () => {
    console.log(`server is listening on port ${config.port}`);
});
