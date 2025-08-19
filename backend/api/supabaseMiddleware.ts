import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { Request, Response, NextFunction } from 'express';

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('ERROR Backend: SUPABASE_URL o SUPABASE_ANON_KEY no están definidos.');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware que agrega el cliente de Supabase a cada solicitud
export const supabaseMiddleware = (req: Request, res: Response, next: NextFunction) => {
  (req as any).supabase = supabase;
  next();
};

export default supabase;