import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { env } from '../../config/env.js';
// In-memory mock users. Replace with DB integration later.
const mockUsers = [
    {
        id: 'u1',
        name: 'Ivy Investigator',
        email: 'ivy@example.com',
        role: 'INVESTIGATOR',
        passwordHash: bcrypt.hashSync('Password123!', 10)
    },
    {
        id: 'u2',
        name: 'Frank Forensic',
        email: 'frank@example.com',
        role: 'ANALYST',
        passwordHash: bcrypt.hashSync('Password123!', 10)
    },
    {
        id: 'u3',
        name: 'Alice Admin',
        email: 'alice@example.com',
        role: 'ADMIN',
        passwordHash: bcrypt.hashSync('Password123!', 10)
    },
    {
        id: 'u4',
        name: 'Judge Judy',
        email: 'judy@example.com',
        role: 'JUDGE',
        passwordHash: bcrypt.hashSync('Password123!', 10)
    }
];
const loginSchema = z.object({
    username: z.string().optional(),
    email: z.string().email().optional(),
    password: z.string().min(8),
    role: z.enum(['INVESTIGATOR', 'ANALYST', 'ADMIN', 'JUDGE']).optional()
});
export async function loginController(req, res) {
    const parse = loginSchema.safeParse(req.body);
    if (!parse.success) {
        return res.status(400).json({ error: 'Invalid request', details: parse.error.flatten() });
    }
    const { email, username, password, role } = parse.data;
    // Look up by email or username (we only have email in mock)
    const user = mockUsers.find(u => u.email === (email ?? username));
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    // If client provided a role selector, ensure it matches stored role
    if (role && role !== user.role) {
        return res.status(403).json({ error: 'Role mismatch' });
    }
    const token = jwt.sign({ sub: user.id, role: user.role, email: user.email }, env.jwtSecret, { expiresIn: '12h' });
    const response = {
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
    };
    return res.json(response);
}
