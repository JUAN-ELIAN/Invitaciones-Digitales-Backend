// import express from 'express';
// import dotenv from 'dotenv';
// import cors from 'cors';
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';
// import ExcelJS from 'exceljs';
// import { createClient } from '@supabase/supabase-js';
// import serverless from 'serverless-http';

// dotenv.config();

// // Interfaces
// interface Rsvp {
//   names: string | string[];
//   participants_count: number;
//   email: string;
//   phone: string;
//   observations: string;
//   confirmed_attendance: boolean;
//   not_attending: boolean;
// }

// // Inicializar Supabase client una sola vez
// const supabaseUrl = process.env.SUPABASE_URL;
// const supabaseKey = process.env.SUPABASE_ANON_KEY;

// if (!supabaseUrl || !supabaseKey) {
//   throw new Error('Las variables de entorno de Supabase no están configuradas.');
// }

// const supabase = createClient(supabaseUrl, supabaseKey);

// const app = express();

// app.use(cors({
//   origin: ['https://invitaciones-digitales-frontend.vercel.app', 'http://localhost:3000'],
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
// }));

// app.use(express.json({ limit: '10mb' }));

// // Middleware para timeout
// app.use((req, res, next) => {
//   // Set timeout de 25 segundos (menos que el límite de Vercel)
//   const timeout = setTimeout(() => {
//     if (!res.headersSent) {
//       res.status(408).json({ error: 'Request timeout' });
//     }
//   }, 25000);

//   res.on('finish', () => clearTimeout(timeout));
//   res.on('close', () => clearTimeout(timeout));
  
//   next();
// });

// // Ruta de health check optimizada
// app.get('/', async (req, res) => {
//   try {
//     res.status(200).json({ 
//       message: 'Backend funcionando correctamente',
//       timestamp: new Date().toISOString(),
//       status: 'healthy'
//     });
//   } catch (error) {
//     res.status(500).json({ error: 'Error interno del servidor' });
//   }
// });

// // Endpoint para registrar una nueva solicitud de acceso
// app.post('/api/register', async (req, res) => {
//   const { email, password } = req.body;
  
//   if (!email || !password) {
//     return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
//   }

//   try {
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);
    
//     const { error } = await supabase
//       .from('users')
//       .insert([{ 
//         email, 
//         password_hash: hashedPassword, 
//         status: 'pending', 
//         access_token: null 
//       }]);

//     if (error) {
//       if ((error as any).code === '23505') {
//         return res.status(409).json({ error: 'El email ya está registrado.' });
//       }
//       throw error;
//     }
    
//     res.status(201).json({ 
//       message: 'Solicitud de registro enviada. Espera la aprobación del administrador.' 
//     });
//   } catch (error: any) {
//     console.error('Error en el registro:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Endpoint para iniciar sesión
// app.post('/api/login', async (req, res) => {
//   const { email, password, access_token } = req.body;
  
//   if (!email || !password || !access_token) {
//     return res.status(400).json({ 
//       error: 'Email, contraseña y token de acceso son requeridos.' 
//     });
//   }

//   try {
//     const { data: user, error } = await supabase
//       .from('users')
//       .select('*')
//       .eq('email', email)
//       .single();
      
//     if (error || !user) {
//       return res.status(404).json({ error: 'Usuario no encontrado.' });
//     }
    
//     if (user.status !== 'approved') {
//       return res.status(403).json({ 
//         error: 'Tu cuenta no ha sido aprobada o está deshabilitada.' 
//       });
//     }
    
//     if (user.access_token !== access_token) {
//       return res.status(401).json({ error: 'Token de acceso inválido.' });
//     }
    
//     const isPasswordValid = await bcrypt.compare(password, user.password_hash);
//     if (!isPasswordValid) {
//       return res.status(401).json({ error: 'Contraseña incorrecta.' });
//     }
    
//     const sessionToken = jwt.sign(
//       { userId: user.id, email: user.email },
//       process.env.JWT_SECRET || 'tu_secreto_jwt_super_secreto',
//       { expiresIn: '7d' }
//     );
    
//     res.status(200).json({ 
//       message: 'Inicio de sesión exitoso', 
//       token: sessionToken 
//     });
//   } catch (error: any) {
//     console.error('Error en el inicio de sesión:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// app.get('/api/invitation/:urlId', async (req, res) => {
//   const { urlId } = req.params;
  
//   try {
//     const { data, error } = await supabase
//       .from('invitations')
//       .select('*')
//       .eq('url_id', urlId)
//       .single();
      
//     if (error || !data) {
//       return res.status(404).json({ error: 'Invitación no encontrada.' });
//     }
    
//     res.status(200).json(data);
//   } catch (error: any) {
//     console.error('Error al obtener invitación:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// app.post('/api/rsvp', async (req, res) => {
//   const { 
//     invitation_id, 
//     names, 
//     participants_count, 
//     email, 
//     phone, 
//     observations, 
//     confirmed_attendance, 
//     not_attending 
//   } = req.body;
  
//   if (!invitation_id || !names || !participants_count || !email || 
//       (confirmed_attendance === undefined && not_attending === undefined)) {
//     return res.status(400).json({ 
//       error: 'Faltan campos obligatorios para la confirmación de asistencia.' 
//     });
//   }

//   try {
//     const { data, error } = await supabase
//       .from('rsvps')
//       .insert([{ 
//         invitation_id, 
//         names, 
//         participants_count, 
//         email, 
//         phone, 
//         observations, 
//         confirmed_attendance, 
//         not_attending 
//       }]);
      
//     if (error) {
//       return res.status(500).json({ error: error.message });
//     }
    
//     res.status(201).json({ 
//       message: 'Confirmación de asistencia registrada con éxito.', 
//       data 
//     });
//   } catch (error: any) {
//     console.error('Error al registrar RSVP:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// app.get('/api/rsvps/:invitationId', async (req, res) => {
//   const { invitationId } = req.params;
  
//   try {
//     const { data, error } = await supabase
//       .from('rsvps')
//       .select('*')
//       .eq('invitation_id', invitationId);
      
//     if (error) {
//       return res.status(404).json({ 
//         error: 'No se encontraron RSVPs para esta invitación.' 
//       });
//     }
    
//     res.status(200).json(data || []);
//   } catch (error: any) {
//     console.error('Error al obtener RSVPs:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// app.get('/api/rsvps/download/:invitationId', async (req, res) => {
//   const { invitationId } = req.params;
  
//   try {
//     const { data: rsvps, error } = await supabase
//       .from('rsvps')
//       .select('*')
//       .eq('invitation_id', invitationId);
      
//     if (error) {
//       return res.status(404).json({ 
//         error: 'No se encontraron RSVPs para esta invitación.' 
//       });
//     }

//     const workbook = new ExcelJS.Workbook();
//     const worksheet = workbook.addWorksheet('Invitados');
    
//     worksheet.columns = [
//       { header: 'Nombre', key: 'names', width: 30 },
//       { header: 'Cantidad de Participantes', key: 'participants_count', width: 25 },
//       { header: 'Email', key: 'email', width: 30 },
//       { header: 'Teléfono', key: 'phone', width: 20 },
//       { header: 'Observaciones', key: 'observations', width: 40 },
//       { header: 'Confirmación de Asistencia', key: 'confirmed_attendance', width: 25 },
//     ];

//     (rsvps || []).forEach((rsvp: Rsvp) => {
//       let namesToDisplay = 'N/A';
//       if (rsvp.names) {
//         if (typeof rsvp.names === 'string') {
//           try {
//             const parsedNames = JSON.parse(rsvp.names);
//             if (Array.isArray(parsedNames)) {
//               namesToDisplay = parsedNames.join(', ');
//             } else {
//               namesToDisplay = rsvp.names;
//             }
//           } catch (e) {
//             namesToDisplay = rsvp.names;
//           }
//         } else if (Array.isArray(rsvp.names)) {
//           namesToDisplay = rsvp.names.join(', ');
//         }
//       }

//       worksheet.addRow({ ...rsvp, names: namesToDisplay });
//     });

//     res.setHeader(
//       'Content-Type', 
//       'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
//     );
//     res.setHeader(
//       'Content-Disposition', 
//       `attachment; filename=invitados_${invitationId}.xlsx`
//     );
    
//     await workbook.xlsx.write(res);
//     res.end();
//   } catch (error: any) {
//     console.error('Error al generar Excel:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Middleware para autenticar el token JWT
// const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && (authHeader as string).split(' ')[1];
  
//   if (token == null || typeof token !== 'string') {
//     return res.sendStatus(401);
//   }
  
//   jwt.verify(token, process.env.JWT_SECRET as string, (err: any, user: any) => {
//     if (err) {
//       return res.sendStatus(403);
//     }
//     (req as any).user = user;
//     next();
//   });
// };

// // Ruta protegida de ejemplo
// app.get('/api/protected', authenticateToken, (req, res) => {
//   res.json({ 
//     message: 'Acceso a ruta protegida concedido', 
//     user: (req as any).user 
//   });
// });

// // Endpoint para obtener las invitaciones del usuario autenticado
// app.get('/api/my-invitations', authenticateToken, async (req, res) => {
//   try {
//     const userId = (req as any).user.userId;
    
//     const { data: userData, error: userError } = await supabase
//       .from('users')
//       .select('accessible_invitations')
//       .eq('id', userId)
//       .single();
      
//     if (userError || !userData) {
//       return res.status(404).json({ error: 'Datos de usuario no encontrados.' });
//     }
    
//     const accessibleInvitationIds = Array.isArray(userData.accessible_invitations) 
//       ? userData.accessible_invitations 
//       : [];
      
//     if (accessibleInvitationIds.length === 0) {
//       return res.status(200).json([]);
//     }
    
//     const { data: invitations, error: invitationsError } = await supabase
//       .from('invitations')
//       .select('*')
//       .in('id', accessibleInvitationIds);
      
//     if (invitationsError) {
//       return res.status(500).json({ 
//         error: 'Error interno del servidor al obtener invitaciones.' 
//       });
//     }
    
//     res.status(200).json(invitations || []);
//   } catch (error: any) {
//     console.error('Error al obtener invitaciones:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Endpoint para otorgar acceso a invitaciones
// app.post('/api/admin/grant-invitation-access', authenticateToken, async (req, res) => {
//   const { targetUserId, invitationId } = req.body;
  
//   if (!targetUserId || !invitationId) {
//     return res.status(400).json({ 
//       error: 'targetUserId e invitationId son requeridos.' 
//     });
//   }

//   try {
//     const requestingUser = (req as any).user.userId;
    
//     const { data: invitation, error: invitationError } = await supabase
//       .from('invitations')
//       .select('user_id')
//       .eq('id', invitationId)
//       .single();
      
//     if (invitationError || !invitation) {
//       return res.status(404).json({ error: 'Invitación no encontrada.' });
//     }
    
//     if (invitation.user_id !== requestingUser) {
//       return res.status(403).json({ 
//         error: 'No tienes permiso para modificar esta invitación.' 
//       });
//     }
    
//     const { data: targetUser, error: targetUserError } = await supabase
//       .from('users')
//       .select('accessible_invitations')
//       .eq('id', targetUserId)
//       .single();
      
//     if (targetUserError || !targetUser) {
//       return res.status(404).json({ error: 'Usuario objetivo no encontrado.' });
//     }
    
//     const currentAccessibleInvitations = Array.isArray(targetUser.accessible_invitations) 
//       ? targetUser.accessible_invitations 
//       : [];
      
//     if (!currentAccessibleInvitations.includes(invitationId)) {
//       currentAccessibleInvitations.push(invitationId);
//     }
    
//     const { error: updateError } = await supabase
//       .from('users')
//       .update({ accessible_invitations: currentAccessibleInvitations })
//       .eq('id', targetUserId);
      
//     if (updateError) {
//       console.error('Error al actualizar accessible_invitations:', updateError.message);
//       return res.status(500).json({ 
//         error: 'Error interno del servidor al otorgar acceso.' 
//       });
//     }
    
//     res.status(200).json({ 
//       message: 'Acceso a la invitación otorgado exitosamente.' 
//     });
//   } catch (error: any) {
//     console.error('Error en /admin/grant-invitation-access:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Exportación para Vercel
// export default serverless(app);

// // Prueba para entorno local
// import express from 'express';
// import dotenv from 'dotenv';
// import cors from 'cors';
// import serverless from 'serverless-http';

// dotenv.config();

// const app = express();


// app.get('/', (_req, res) => {
//   res.json({ message: 'Bienvenido a la API de invitaciones digitales.' });
// });

// const router = express.Router();

// app.use(cors({
//   origin: 'https://invitaciones-digitales-frontend.vercel.app',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
// }));

// app.use(express.json());

// // Montar el enrutador en el path '/api'
// app.use('/api', router);

// // Si estás probando localmente
// if (process.env.NODE_ENV !== 'production') {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`Server is running on http://localhost:${PORT}`);
//   });
// }

// // Exportación final para Vercel
// export default serverless(app);

import cors from 'cors';
import { IncomingMessage, ServerResponse } from 'http';
import { createClient } from '@supabase/supabase-js';
import { parse } from 'url';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// Interfaces
interface JwtPayload {
  userId: string;
  email: string;
  iat?: number;
  exp?: number;
}

// Inicializar Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const jwtSecret = process.env.JWT_SECRET || 'tu_secreto_jwt_super_secreto';

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Las variables de entorno de Supabase no están configuradas.');
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Función helper para verificar JWT
function verifyJWT(token: string): Promise<JwtPayload> {
  return new Promise((resolve, reject) => {
    jwt.verify(token, jwtSecret, (err, decoded) => {
      if (err) {
        reject(new Error('Token inválido o expirado'));
      } else {
        resolve(decoded as JwtPayload);
      }
    });
  });
}

// Función principal para manejar las solicitudes
export default async function handler(req: IncomingMessage, res: ServerResponse) {
  // Configuración de CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }

  const { pathname } = parse(req.url || '/', true);

  try {
    if (pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        message: 'Backend funcionando correctamente',
        timestamp: new Date().toISOString(),
        status: 'healthy',
        version: '1.0'
      }));
      return;
    }

    if (req.method === 'POST' && pathname === '/api/register') {
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const { email, password } = JSON.parse(body);

      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Faltan campos obligatorios' }));
        return;
      }

      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const { data, error } = await supabase
        .from('users')
        .insert([{ email, password_hash: hashedPassword, status: 'approved', accessible_invitations: [] }])
        .select();

      if (error) {
        if (error.code === '23505') {
          res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'El email ya está registrado' }));
        } else {
          res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Error al registrar el usuario', message: error.message }));
        }
        return;
      }
      res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ message: 'Usuario registrado exitosamente', data }));
      return;
    }

    if (req.method === 'POST' && pathname === '/api/login') {
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const { email, password } = JSON.parse(body);

      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Faltan campos obligatorios' }));
        return;
      }

      const { data: userData, error: userError } = await supabase.from('users').select('*').eq('email', email).single();

      if (userError || !userData) {
        res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Credenciales inválidas' }));
        return;
      }

      const passwordMatch = await bcrypt.compare(password, userData.password_hash);
      if (!passwordMatch) {
        res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Credenciales inválidas' }));
        return;
      }

      const token = jwt.sign({ userId: userData.id, email: userData.email }, jwtSecret, { expiresIn: '7d' });
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ message: 'Login exitoso', token }));
      return;
    }

    if (req.method === 'POST' && pathname === '/api/rsvp') {
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const {
        invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending, song_suggestions
      } = JSON.parse(body);

      if (!invitation_id || !names || typeof confirmed_attendance === 'undefined') {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Faltan campos obligatorios' }));
        return;
      }

      const rsvpData: any = { invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending };

      if (song_suggestions && typeof song_suggestions === 'string') {
        rsvpData.song_suggestions = song_suggestions.trim().slice(0, 255);
      }

      const { data, error } = await supabase.from('rsvps').insert([rsvpData]).select();

      if (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Error al registrar la asistencia', message: error.message }));
        return;
      }
      res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ message: 'Asistencia registrada exitosamente', data }));
      return;
    }

    if (req.method === 'PUT' && pathname && pathname.startsWith('/api/rsvp/')) {
      const rsvpId = pathname.split('/')[3];
      if (!rsvpId) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Falta el ID del RSVP' }));
        return;
      }
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const payload = JSON.parse(body || '{}');
      const allowedFields = ['names', 'participants_count', 'email', 'phone', 'observations', 'confirmed_attendance', 'not_attending'];
      const updateData: any = {};
      for (const key of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(payload, key)) {
          updateData[key] = payload[key];
        }
      }

      if (Object.prototype.hasOwnProperty.call(payload, 'song_suggestions')) {
        const { song_suggestions } = payload;
        if (song_suggestions === null) {
          updateData.song_suggestions = null;
        } else if (typeof song_suggestions === 'string') {
          updateData.song_suggestions = song_suggestions.trim().slice(0, 255);
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'song_suggestions debe ser una cadena de texto' }));
          return;
        }
      }

      if (Object.keys(updateData).length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'No hay campos válidos para actualizar' }));
        return;
      }

      const { data, error } = await supabase.from('rsvps').update(updateData).eq('id', rsvpId).select();

      if (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Error al actualizar la asistencia', message: error.message }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ message: 'Asistencia actualizada exitosamente', data }));
      return;
    }

    if (req.method === 'PUT' && pathname === '/api/rsvp') {
      let body = '';
      for await (const chunk of req) { body += chunk; }
      const payload = JSON.parse(body || '{}');
      const { invitation_id, email } = payload;

      if (!invitation_id || !email) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'invitation_id y email son requeridos para la actualización' }));
        return;
      }

      const allowedFields = ['names','participants_count','phone','observations','confirmed_attendance','not_attending'];
      const updateData: any = {};
      for (const key of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(payload, key)) {
          updateData[key] = payload[key];
        }
      }

      if (Object.prototype.hasOwnProperty.call(payload, 'song_suggestions')) {
        const { song_suggestions } = payload;
        if (song_suggestions === null) {
          updateData.song_suggestions = null;
        } else if (typeof song_suggestions === 'string') {
          updateData.song_suggestions = song_suggestions.trim().slice(0, 255);
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'song_suggestions debe ser una cadena de texto' }));
          return;
        }
      }

      if (Object.keys(updateData).length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'No hay campos válidos para actualizar' }));
        return;
      }

      const { data, error } = await supabase.from('rsvps').update(updateData).eq('invitation_id', invitation_id).eq('email', email).select();

      if (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Error al actualizar la asistencia', message: error.message }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ message: 'Asistencia actualizada exitosamente', data }));
      return;
    }

  } catch (error: any) {
    console.error('Error en el handler:', error.message);
    res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ 
      error: 'Error interno del servidor', 
      message: error.message 
    }));
  }
}