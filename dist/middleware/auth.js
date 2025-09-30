import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
export function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ')
        ? authHeader.slice('Bearer '.length)
        : undefined;
    if (!token) {
        return res.status(401).json({ error: 'Missing token' });
    }
    try {
        const decoded = jwt.verify(token, env.jwtSecret);
        req.user = decoded;
        return next();
    }
    catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
export function requireRole(...allowed) {
    return (req, res, next) => {
        const user = req.user;
        if (!user)
            return res.status(401).json({ error: 'Unauthorized' });
        if (!allowed.includes(user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        return next();
    };
}
