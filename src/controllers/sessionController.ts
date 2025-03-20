import { Request, Response } from 'express';
import supabase from '../utils/supabase';
import { AuthenticatedRequest } from '../types/auth';

/**
 * Get current user session
 */
export const getSession = async (req: AuthenticatedRequest, res: Response) => {
  try {
    console.log(`[SESSION] Processing session request for IP: ${req.ip}`);
    
    // Проверка наличия auth-token
    const token = req.cookies['auth-token'];
    if (!token) {
      console.log('[SESSION] No auth-token cookie found');
      return res.status(401).json({
        message: 'Not authenticated',
        code: 'NOT_AUTHENTICATED'
      });
    }

    console.log('[SESSION] Found auth-token, validating with Supabase');
    // Verify token with Supabase
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data || !data.user) {
      console.log(`[SESSION] Token validation failed: ${error?.message || 'No user data'}`);
      
      // Проверка наличия refresh-token для потенциального обновления
      const refreshToken = req.cookies['refresh-token'];
      if (refreshToken) {
        console.log('[SESSION] Found refresh-token, attempting to refresh session');
        // Try to refresh session
        try {
          const { data: refreshData, error: refreshError } = await supabase.auth.refreshSession({
            refresh_token: refreshToken
          });
          
          if (refreshError || !refreshData.session || !refreshData.user) {
            console.error(`[SESSION] Session refresh failed: ${refreshError?.message || 'No data'}`);
            clearAuthCookies(res);
            return res.status(401).json({
              message: 'Session expired',
              code: 'SESSION_EXPIRED'
            });
          }
          
          // Log successful refresh
          console.log(`[SESSION] Session refreshed successfully for user: ${refreshData.user.email}`);
          
          // Обработка информации о сроке истечения токена
          const expiresAtRaw = refreshData.session.expires_at;
          const expiresAtDate = new Date(expiresAtRaw!);
          const expiresAtMs = expiresAtDate.getTime();
          const now = Date.now();
          const timeUntilExpiry = expiresAtMs - now;
          
          console.log(`[SESSION] New token expires at: ${expiresAtDate.toISOString()}`);
          console.log(`[SESSION] Time until expiry: ${timeUntilExpiry}ms (${Math.floor(timeUntilExpiry/1000/60)} minutes)`);
          
          // Set new tokens in cookies
          setAuthCookies(res, refreshData.session.access_token, refreshData.session.refresh_token);
          
          // Get user profile
          const { data: profile } = await supabase
            .from('profiles')
            .select('*')
            .eq('user_id', refreshData.user.id)
            .single();
          
          // Return updated user info
          return res.status(200).json({
            user: {
              id: refreshData.user.id,
              email: refreshData.user.email,
              profile: profile
            },
            expiresAt: expiresAtMs
          });
        } catch (refreshErr) {
          console.error('[SESSION] Unexpected error during session refresh:', refreshErr);
          clearAuthCookies(res);
          return res.status(401).json({
            message: 'Invalid session',
            code: 'INVALID_SESSION'
          });
        }
      }
      
      // No refresh token, return error
      clearAuthCookies(res);
      return res.status(401).json({
        message: 'Session expired',
        code: 'SESSION_EXPIRED'
      });
    }

    // Token is valid, get user profile
    console.log(`[SESSION] Token valid for user: ${data.user.email}`);
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', data.user.id)
      .single();

    // Получаем срок действия токена
    const { data: sessionData } = await supabase.auth.getSession();
    if (!sessionData.session) {
      console.error('[SESSION] Failed to get session data from Supabase');
      return res.status(500).json({
        message: 'Failed to get session data',
        code: 'SESSION_ERROR'
      });
    }
    
    // Обработка информации о сроке истечения токена
    const expiresAtRaw = sessionData.session.expires_at;
    const expiresAtDate = new Date(expiresAtRaw!);
    const expiresAtMs = expiresAtDate.getTime();
    const now = Date.now();
    const timeUntilExpiry = expiresAtMs - now;
    
    console.log(`[SESSION] Token expires at: ${expiresAtDate.toISOString()}`);
    console.log(`[SESSION] Time until expiry: ${timeUntilExpiry}ms (${Math.floor(timeUntilExpiry/1000/60)} minutes)`);

    // Return user information
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email,
        profile: profile
      },
      expiresAt: expiresAtMs
    });
  } catch (err) {
    console.error('[SESSION] Unexpected error in getSession:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

// Функции для работы с куками (дублирование из authMiddleware для изоляции)
// В идеале следует вынести в отдельный модуль для повторного использования

function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
  const isProd = process.env.NODE_ENV === 'production';
  const secureCookie = isProd;
  const cookieDomain = isProd ? '.eneca.work' : undefined;
  
  console.log(`[COOKIES] Setting auth cookies in session controller: domain=${cookieDomain}, secure=${secureCookie}`);
  
  // Access token cookie
  res.cookie('auth-token', accessToken, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  });
  
  // Refresh token cookie
  res.cookie('refresh-token', refreshToken, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
  });
}

function clearAuthCookies(res: Response) {
  const isProd = process.env.NODE_ENV === 'production';
  const cookieDomain = isProd ? '.eneca.work' : undefined;
  
  console.log(`[COOKIES] Clearing auth cookies in session controller: domain=${cookieDomain}`);
  
  res.clearCookie('auth-token', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/'
  });
  
  res.clearCookie('refresh-token', {
    httpOnly: true, 
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/'
  });
} 