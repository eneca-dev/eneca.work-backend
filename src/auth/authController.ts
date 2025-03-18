import { Request, Response } from 'express';
import supabase from '../utils/supabase';
import { LoginRequest, AuthenticatedRequest } from '../types/auth';

/**
 * Handle user login
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password }: LoginRequest = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Authenticate with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    // Handle authentication error
    if (error) {
      console.error(`Auth error for user ${email}:`, error.message);
      return res.status(401).json({
        message: 'Authentication failed',
        code: 'AUTH_FAILED'
      });
    }

    // Get user profile
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', data.user.id)
      .single();

    // Log successful login
    console.info(`User ${email} logged in successfully | ${new Date().toISOString()}`);
    
    // Set auth token in HTTP-only cookie
    res.cookie('auth-token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    });

    // Return user information (without sending the token in response body)
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email,
        profile: profile
      },
      expiresAt: new Date(data.session.expires_at!).getTime()
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Handle user logout
 */
export const logout = async (req: Request, res: Response) => {
  try {
    // Sign out from Supabase
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      console.error('Logout error:', error.message);
      return res.status(500).json({
        message: 'Failed to logout',
        code: 'LOGOUT_ERROR'
      });
    }
    
    // Clear the auth cookie
    res.clearCookie('auth-token');
    
    return res.status(200).json({
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Get current user session
 */
export const getSession = async (req: AuthenticatedRequest, res: Response) => {
  try {
    // User is already authenticated by middleware
    if (!req.user) {
      return res.status(401).json({
        message: 'Not authenticated',
        code: 'AUTH_REQUIRED'
      });
    }

    // Get user profile from Supabase
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', req.user.id)
      .single();

    // Return user session data
    return res.status(200).json({
      user: {
        id: req.user.id,
        email: req.user.email,
        profile: profile
      },
      expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000) // Approximation based on cookie expiry
    });
  } catch (err) {
    console.error('Get session error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
}; 