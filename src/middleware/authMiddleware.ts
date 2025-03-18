import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import supabase from '../utils/supabase';

/**
 * Middleware to authenticate requests using JWT from cookies
 */
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get token from cookie
    const token = req.cookies['auth-token'];
    
    if (!token) {
      return res.status(401).json({
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Verify token with Supabase
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      res.clearCookie('auth-token'); // Clear invalid token
      return res.status(401).json({
        message: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Attach user to request
    req.user = {
      id: data.user.id,
      email: data.user.email!,
      role: data.user.role || 'user'
    };

    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
}; 