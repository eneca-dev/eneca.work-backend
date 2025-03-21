import { Response } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import supabase from '../utils/supabase';

/**
 * Получение профиля пользователя с учетом связанных данных
 */
export const getProfile = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Пользователь не аутентифицирован' });
    }

    // Получаем профиль с присоединенными данными из справочников
    const { data, error } = await supabase
      .from('profiles')
      .select(`
        *,
        departments:department_id (department_id, department_name),
        teams:team_id (team_id, team_name),
        positions:position_id (position_id, position_name),
        categories:category_id (category_id, category_name)
      `)
      .eq('user_id', userId)
      .single();

    if (error) {
      console.error('Ошибка получения профиля:', error);
      return res.status(500).json({ error: 'Ошибка при получении данных профиля' });
    }

    if (!data) {
      return res.status(404).json({ error: 'Профиль не найден' });
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error('Ошибка обработки запроса профиля:', error);
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
};

/**
 * Обновление профиля пользователя
 */
export const updateProfile = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Пользователь не аутентифицирован' });
    }

    const { first_name, last_name, department_id, team_id, position_id, category_id } = req.body;

    // Валидация данных
    if (!first_name || !last_name) {
      return res.status(400).json({ error: 'Имя и фамилия обязательны для заполнения' });
    }

    // Обновление данных профиля
    const { data, error } = await supabase
      .from('profiles')
      .update({
        first_name,
        last_name,
        department_id,
        team_id,
        position_id,
        category_id
      })
      .eq('user_id', userId)
      .select();

    if (error) {
      console.error('Ошибка обновления профиля:', error);
      return res.status(500).json({ error: 'Ошибка при обновлении данных профиля' });
    }

    return res.status(200).json(data[0]);
  } catch (error) {
    console.error('Ошибка обработки запроса обновления профиля:', error);
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
};

/**
 * Получение справочных данных
 */
export const getReferences = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { type } = req.params;
    let data = null;
    let error = null;

    // Выбор таблицы в зависимости от типа справочника
    switch (type) {
      case 'departments':
        ({ data, error } = await supabase
          .from('departments')
          .select('department_id, department_name')
          .order('department_name'));
        break;
      
      case 'teams':
        // Опционально можно фильтровать по департаменту
        const departmentId = req.query.department_id as string;
        const query = supabase
          .from('teams')
          .select('team_id, team_name, department_id');
        
        if (departmentId) {
          query.eq('department_id', departmentId);
        }
        
        ({ data, error } = await query.order('team_name'));
        break;
      
      case 'positions':
        ({ data, error } = await supabase
          .from('positions')
          .select('position_id, position_name')
          .order('position_name'));
        break;
      
      case 'categories':
        ({ data, error } = await supabase
          .from('categories')
          .select('category_id, category_name')
          .order('category_name'));
        break;
      
      default:
        return res.status(400).json({ error: 'Неизвестный тип справочника' });
    }

    if (error) {
      console.error(`Ошибка получения справочника ${type}:`, error);
      return res.status(500).json({ error: `Ошибка при получении справочника ${type}` });
    }

    return res.status(200).json(data);
  } catch (error) {
    console.error('Ошибка обработки запроса справочника:', error);
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
}; 