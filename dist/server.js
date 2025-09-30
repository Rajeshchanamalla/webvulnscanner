import dotenv from 'dotenv';
dotenv.config();
import http from 'http';
import app from './app.js';
import { env } from './config/env.js';
const server = http.createServer(app);
server.listen(env.port, () => {
    // eslint-disable-next-line no-console
    console.log(`API listening on http://localhost:${env.port}`);
});
process.on('SIGINT', () => {
    server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
});
