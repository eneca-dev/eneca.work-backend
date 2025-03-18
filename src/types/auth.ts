import { Request } from 'express';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface User {
  id: string;
  email: string;
  role: string;
}

export interface AuthenticatedRequest extends Request {
  user?: User;
}

export interface LoginResponse {
  user: {
    id: string;
    email: string;
    profile?: any;
  };
  expiresAt: number;
}

export interface ErrorResponse {
  message: string;
  code: string;
} 