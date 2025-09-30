export type UserRole =
  | 'INVESTIGATOR'
  | 'ANALYST'
  | 'ADMIN'
  | 'JUDGE';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
}

export interface LoginRequestBody {
  username?: string; // username or email supported
  email?: string;
  password: string;
  role?: UserRole; // optional selector to guide redirection
}

export interface LoginResponseBody {
  token: string;
  user: AuthenticatedUser;
}
