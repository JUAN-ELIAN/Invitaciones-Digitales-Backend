export default async function handler(req: any, res: any) {
  try {
    const startTime = Date.now();
    
    // Test de variables de entorno
    const envCheck = {
      SUPABASE_URL: process.env.SUPABASE_URL ? 'SET' : 'MISSING',
      SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY ? 'SET' : 'MISSING',
      JWT_SECRET: process.env.JWT_SECRET ? 'SET' : 'MISSING',
      NODE_ENV: process.env.NODE_ENV || 'undefined'
    };
    
    // Test de imports básicos
    let importTests = {};
    
    try {
      await import('express');
      importTests = { ...importTests, express: 'OK' };
    } catch (e) {
      importTests = { ...importTests, express: 'ERROR' };
    }
    
    try {
      await import('@supabase/supabase-js');
      importTests = { ...importTests, supabase: 'OK' };
    } catch (e) {
      importTests = { ...importTests, supabase: 'ERROR' };
    }
    
    try {
      await import('bcrypt');
      importTests = { ...importTests, bcrypt: 'OK' };
    } catch (e) {
      importTests = { ...importTests, bcrypt: 'ERROR' };
    }
    
    const endTime = Date.now();
    
    return res.status(200).json({
      message: 'Diagnóstico completado',
      duration: `${endTime - startTime}ms`,
      environment: envCheck,
      imports: importTests,
      vercel: {
        region: process.env.VERCEL_REGION || 'unknown',
        runtime: 'nodejs'
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error: any) {
    return res.status(500).json({
      error: 'Error en diagnóstico',
      message: error.message,
      stack: error.stack?.split('\n').slice(0, 3)
    });
  }
}