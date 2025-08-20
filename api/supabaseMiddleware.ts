import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { Request, Response, NextFunction } from 'express';

dotenv.config();

// Middleware que crea el cliente de Supabase y lo adjunta a la solicitud.
export const supabaseMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    // Si las variables de entorno no están definidas,
    // se devuelve un error de forma controlada en lugar de detener el proceso.
    return res.status(500).json({
      error: 'Las variables de entorno de Supabase no están configuradas.'
    });
  }

  // Creamos el cliente dentro del middleware.
  const supabase = createClient(supabaseUrl, supabaseKey);
  (req as any).supabase = supabase;
  
  next();
};