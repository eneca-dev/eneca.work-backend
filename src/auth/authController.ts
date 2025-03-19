import { Request, Response } from 'express';
import supabase from '../utils/supabase';
import { LoginRequest, AuthenticatedRequest } from '../types/auth';

// Хранилище для отслеживания последних обновлений токенов пользователей
// userId или IP -> timestamp последнего обновления
const tokenRefreshRateLimit = new Map<string, number>();
// Минимальный интервал между обновлениями токена (в мс) - 15 минут
const MIN_REFRESH_INTERVAL = 15 * 60 * 1000;

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

    // Set refresh token in HTTP-only cookie
    res.cookie('refresh-token', data.session.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
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
    
    // Clear the auth cookies
    res.clearCookie('auth-token');
    res.clearCookie('refresh-token');
    
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
 * Refresh user token
 */
export const refreshToken = async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies['refresh-token'];
    
    if (!refreshToken) {
      return res.status(401).json({
        message: 'Refresh token not found',
        code: 'REFRESH_TOKEN_MISSING'
      });
    }
    
    // Проверка частоты обновления токена
    const clientIP = req.ip || 'unknown';
    const clientId = refreshToken.substring(0, 20); // Используем часть токена как идентификатор
    const key = `${clientId}:${clientIP}`;
    const lastRefresh = tokenRefreshRateLimit.get(key) || 0;
    const now = Date.now();
    
    // Если с последнего обновления прошло недостаточно времени, отклоняем запрос
    if (now - lastRefresh < MIN_REFRESH_INTERVAL) {
      console.log(`Rate limiting token refresh from ${clientIP} - ${Math.floor((now - lastRefresh) / 1000)} seconds since last refresh`);
      return res.status(429).json({
        message: 'You are refreshing tokens too frequently. Please try again later.',
        code: 'REFRESH_RATE_LIMITED',
        retryAfter: Math.ceil((MIN_REFRESH_INTERVAL - (now - lastRefresh)) / 1000)
      });
    }
    
    // Refresh session using Supabase
    const { data, error } = await supabase.auth.refreshSession({ 
      refresh_token: refreshToken 
    });
    
    if (error || !data || !data.session || !data.user) {
      console.error('Token refresh error:', error?.message || 'Session data missing');
      res.clearCookie('auth-token');
      res.clearCookie('refresh-token');
      
      return res.status(401).json({
        message: 'Failed to refresh token',
        code: 'REFRESH_FAILED'
      });
    }
    
    // Обновляем информацию о последнем обновлении
    tokenRefreshRateLimit.set(key, now);
    
    // Периодически очищаем старые записи (старше 24 часов)
    const ONE_DAY = 24 * 60 * 60 * 1000;
    for (const [mapKey, timestamp] of tokenRefreshRateLimit.entries()) {
      if (now - timestamp > ONE_DAY) {
        tokenRefreshRateLimit.delete(mapKey);
      }
    }
    
    // Set new tokens in cookies
    res.cookie('auth-token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    });
    
    res.cookie('refresh-token', data.session.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
    });
    
    // Log successful token refresh
    console.info(`Token refreshed for user ${data.user.email} | ${new Date().toISOString()}`);
    
    // Return updated user information
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email
      },
      expiresAt: new Date(data.session.expires_at!).getTime()
    });
  } catch (err) {
    console.error('Token refresh error:', err);
    // Clear cookies on error
    res.clearCookie('auth-token');
    res.clearCookie('refresh-token');
    
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