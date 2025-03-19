import { Request, Response } from 'express';
import supabase from '../utils/supabase';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

// Клиент с административными правами для операций удаления
const adminSupabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY!
);

/**
 * Handle user registration
 */
export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Validate input data
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({
        message: 'Все поля обязательны для заполнения',
        code: 'MISSING_FIELDS'
      });
    }

    // Default values for required fields
    const defaultValues = {
      department_id: "42c93225-0ac5-41fe-820a-5ecbe33b5e2d", // "Без отдела"
      team_id: "983b9ae6-6bcf-472d-ba26-eee2e4673787",       // "Без команды"
      position_id: "90ecd7f2-b969-4a0d-bba7-226cf0cb8e7b",   // "Без должности"
      category_id: "7b20a482-b5e0-40b4-9cb8-bf5e3f1a0e3f",   // "Без категории"
      user_role_id: "3ac4f27e-c94c-4b0d-b750-9fb6366b85bc"   // Роль "user"
    };

    // Register with Supabase
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          first_name: firstName,
          last_name: lastName,
          full_name: `${firstName} ${lastName}`
        },
        emailRedirectTo: `${process.env.FRONTEND_URL}/auth/email-confirmed`
      }
    });

    // Handle registration errors
    if (error) {
      if (error.message.includes('already exists')) {
        return res.status(409).json({
          message: 'Email уже зарегистрирован',
          code: 'EMAIL_EXISTS'
        });
      }
      
      if (error.message.includes('password')) {
        return res.status(400).json({
          message: 'Пароль слишком слабый',
          code: 'WEAK_PASSWORD'
        });
      }
      
      return res.status(500).json({
        message: error.message,
        code: 'REGISTRATION_FAILED'
      });
    }

    // Create profile record
    if (data && data.user) {
      const { error: profileError } = await supabase
        .from('profiles')
        .insert({
          user_id: data.user.id,
          first_name: firstName,
          last_name: lastName,
          email,
          department_id: defaultValues.department_id,
          team_id: defaultValues.team_id,
          position_id: defaultValues.position_id,
          category_id: defaultValues.category_id,
          role_id: defaultValues.user_role_id
        });

      if (profileError) {
        console.error('Profile creation error:', profileError);
        
        try {
          // Используем adminSupabase для удаления пользователя с service key
          const { error: deleteError } = await adminSupabase.auth.admin.deleteUser(
            data.user.id
          );
          
          if (deleteError) {
            console.error('Failed to delete user after profile creation error:', deleteError);
          } else {
            console.log(`Successfully deleted user ${data.user.id} after profile creation error`);
          }
        } catch (deleteErr) {
          console.error('Exception when deleting user:', deleteErr);
        }
        
        return res.status(500).json({
          message: 'Не удалось создать запись пользователя',
          code: 'USER_CREATION_FAILED'
        });
      }
    }

    // Successful response
    return res.status(200).json({
      message: 'Регистрация успешна. Проверьте email для подтверждения.',
      user: {
        id: data?.user?.id,
        email: data?.user?.email
      }
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({
      message: 'Внутренняя ошибка сервера',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Resend confirmation email
 */
export const resendConfirmation = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        message: 'Email обязателен',
        code: 'MISSING_EMAIL'
      });
    }
    
    // Resend confirmation email
    const { error } = await supabase.auth.resend({
      type: 'signup',
      email,
      options: {
        emailRedirectTo: `${process.env.FRONTEND_URL}/auth/email-confirmed`
      }
    });
    
    if (error) {
      return res.status(500).json({
        message: error.message,
        code: 'RESEND_FAILED'
      });
    }
    
    return res.status(200).json({
      message: 'Письмо с подтверждением успешно отправлено повторно'
    });
  } catch (err) {
    console.error('Resend confirmation error:', err);
    return res.status(500).json({
      message: 'Не удалось повторно отправить письмо подтверждения',
      code: 'RESEND_FAILED'
    });
  }
}; 