// import express from 'express';
// import dotenv from 'dotenv';
// import cors from 'cors';
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';
// import ExcelJS from 'exceljs';
// import { supabaseMiddleware } from './supabaseMiddleware'
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

// const app = express();

// app.use(cors({
//   origin: 'https://invitaciones-digitales-frontend.vercel.app',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
// }));

// app.use(express.json());

// // Aplica el middleware antes de las rutas.
// app.use(supabaseMiddleware);

// const router = express.Router();

// app.get('/', (_req, res) => {
//   res.json({ message: 'Backend funcionando correctamente' });
// });

// // Endpoint para registrar una nueva solicitud de acceso
// router.post('/register', async (req, res) => {
//   const { email, password } = req.body;
//   const supabase = (req as any).supabase;
//   if (!email || !password) {
//     return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
//   }

//   try {
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);
//     const { error } = await supabase
//       .from('users')
//       .insert([{ email, password_hash: hashedPassword, status: 'pending', access_token: null }])
//       .select()
//       .single();

//     if (error) {
//       if ((error as any).code === '23505') {
//         return res.status(409).json({ error: 'El email ya está registrado.' });
//       }
//       throw error;
//     }
//     res.status(201).json({ message: 'Solicitud de registro enviada. Espera la aprobación del administrador.' });
//   } catch (error: any) {
//     console.error('Error en el registro:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Endpoint para iniciar sesión
// router.post('/login', async (req, res) => {
//   const { email, password, access_token } = req.body;
//   const supabase = (req as any).supabase;
//   if (!email || !password || !access_token) {
//     return res.status(400).json({ error: 'Email, contraseña y token de acceso son requeridos.' });
//   }

//   try {
//     const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
//     if (error || !user) {
//       return res.status(404).json({ error: 'Usuario no encontrado.' });
//     }
//     if (user.status !== 'approved') {
//       return res.status(403).json({ error: 'Tu cuenta no ha sido aprobada o está deshabilitada.' });
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
//     res.status(200).json({ message: 'Inicio de sesión exitoso', token: sessionToken });
//   } catch (error: any) {
//     console.error('Error en el inicio de sesión:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// router.get('/invitation/:urlId', async (req, res) => {
//   const { urlId } = req.params;
//   const supabase = (req as any).supabase;
//   try {
//     const { data, error } = await supabase.from('invitations').select('*').eq('url_id', urlId).single();
//     if (error) {
//       return res.status(404).json({ error: 'Invitación no encontrada.' });
//     }
//     if (!data) {
//       return res.status(404).json({ error: 'Invitación no encontrada.' });
//     }
//     res.status(200).json(data);
//   } catch (error: any) {
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// router.post('/rsvp', async (req, res) => {
//   const { invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending } = req.body;
//   if (!invitation_id || !names || !participants_count || !email || (confirmed_attendance === undefined && not_attending === undefined)) {
//     return res.status(400).json({ error: 'Faltan campos obligatorios para la confirmación de asistencia.' });
//   }

//   try {
//     const supabase = (req as any).supabase;
//     const { data, error } = await supabase
//       .from('rsvps')
//       .insert([{ invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending }]);
//     if (error) {
//       return res.status(500).json({ error: error.message });
//     }
//     res.status(201).json({ message: 'Confirmación de asistencia registrada con éxito.', data });
//   } catch (error: any) {
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// router.get('/rsvps/:invitationId', async (req, res) => {
//   const { invitationId } = req.params;
//   const supabase = (req as any).supabase;
//   try {
//     const { data, error } = await supabase.from('rsvps').select('*').eq('invitation_id', invitationId);
//     if (error) {
//       return res.status(404).json({ error: 'No se encontraron RSVPs para esta invitación.' });
//     }
//     res.status(200).json(data);
//   } catch (error: any) {
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// router.get('/rsvps/download/:invitationId', async (req, res) => {
//   const { invitationId } = req.params;
//   const supabase = (req as any).supabase;
//   try {
//     const { data: rsvps, error } = await supabase.from('rsvps').select('*').eq('invitation_id', invitationId);
//     if (error) {
//       return res.status(404).json({ error: 'No se encontraron RSVPs para esta invitación.' });
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

//     res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
//     res.setHeader('Content-Disposition', `attachment; filename=invitados_${invitationId}.xlsx`);
//     await workbook.xlsx.write(res);
//     res.end();
//   } catch (error: any) {
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
// router.get('/protected', authenticateToken, (req, res) => {
//   res.json({ message: 'Acceso a ruta protegida concedido', user: (req as any).user });
// });

// // Nuevo endpoint para obtener las invitaciones del usuario autenticado
// router.get('/my-invitations', authenticateToken, async (req, res) => {
//   try {
//     const userId = (req as any).user.userId;
//     const supabase = (req as any).supabase;
//     const { data: userData, error: userError } = await supabase.from('users').select('accessible_invitations').eq('id', userId).single();
//     if (userError || !userData) {
//       return res.status(404).json({ error: 'Datos de usuario no encontrados.' });
//     }
//     const accessibleInvitationIds = Array.isArray(userData.accessible_invitations) ? userData.accessible_invitations : [];
//     if (accessibleInvitationIds.length === 0) {
//       return res.status(200).json([]);
//     }
//     const { data: invitations, error: invitationsError } = await supabase.from('invitations').select('*').in('id', accessibleInvitationIds);
//     if (invitationsError) {
//       return res.status(500).json({ error: 'Error interno del servidor al obtener invitaciones.' });
//     }
//     res.status(200).json(invitations);
//   } catch (error: any) {
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Nuevo endpoint para otorgar acceso a invitaciones
// router.post('/admin/grant-invitation-access', authenticateToken, async (req, res) => {
//   const { targetUserId, invitationId } = req.body;
//   if (!targetUserId || !invitationId) {
//     return res.status(400).json({ error: 'targetUserId e invitationId son requeridos.' });
//   }

//   try {
//     const requestingUser = (req as any).user.userId;
//     const supabase = (req as any).supabase;
//     const { data: invitation, error: invitationError } = await supabase.from('invitations').select('user_id').eq('id', invitationId).single();
//     if (invitationError || !invitation) {
//       return res.status(404).json({ error: 'Invitación no encontrada.' });
//     }
//     if (invitation.user_id !== requestingUser) {
//       return res.status(403).json({ error: 'No tienes permiso para modificar esta invitación.' });
//     }
//     const { data: targetUser, error: targetUserError } = await supabase.from('users').select('accessible_invitations').eq('id', targetUserId).single();
//     if (targetUserError || !targetUser) {
//       return res.status(404).json({ error: 'Usuario objetivo no encontrado.' });
//     }
//     const currentAccessibleInvitations = Array.isArray(targetUser.accessible_invitations) ? targetUser.accessible_invitations : [];
//     if (!currentAccessibleInvitations.includes(invitationId)) {
//       currentAccessibleInvitations.push(invitationId);
//     }
//     const { error: updateError } = await supabase
//       .from('users')
//       .update({ accessible_invitations: currentAccessibleInvitations })
//       .eq('id', targetUserId);
//     if (updateError) {
//       console.error('Error al actualizar accessible_invitations:', updateError.message);
//       return res.status(500).json({ error: 'Error interno del servidor al otorgar acceso.' });
//     }
//     res.status(200).json({ message: 'Acceso a la invitación otorgado exitosamente.' });
//   } catch (error: any) {
//     console.error('Error en /admin/grant-invitation-access:', error.message);
//     res.status(500).json({ error: 'Error interno del servidor.' });
//   }
// });

// // Montar el enrutador en el path '/api'
// app.use('/api', router);

// // Exportación final para Vercel
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



// api/index.ts
import express from 'express';
import serverless from 'serverless-http';

// Elimina todas las demás importaciones por ahora
// (dotenv, cors, bcrypt, etc.)
// Elimina todas las demás configuraciones (app.use, router)

const app = express();

app.get('/', (_req, res) => {
  res.json({ message: 'Backend funcionando correctamente' });
});

// Esto debe quedar al final del archivo
export default serverless(app);