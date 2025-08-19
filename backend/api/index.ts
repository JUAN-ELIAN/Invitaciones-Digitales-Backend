import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import ExcelJS from 'exceljs';
import serverless from 'serverless-http';

dotenv.config();

// 1. Inicialización de Supabase: esta es la parte más crítica.
//    Se inicializa de forma inmediata al cargar la función.
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('ERROR Backend: SUPABASE_URL o SUPABASE_ANON_KEY no están definidos.');
  // Terminar el proceso si no se pueden obtener las variables.
  process.exit(1); 
}

const supabase = createClient(supabaseUrl, supabaseKey);
console.log('DEBUG Backend: Supabase cliente inicializado.');

// Interfaces
interface Rsvp {
  names: string | string[];
  participants_count: number;
  email: string;
  phone: string;
  observations: string;
  confirmed_attendance: boolean;
  not_attending: boolean;
}

const app = express();

app.use(cors({
  origin: 'https://invitaciones-digitales-frontend.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());

app.options('*', cors());
app.options('*', (_req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://invitaciones-digitales-frontend.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// 2. Aquí van todas tus rutas (endpoints)
// Endpoint de prueba
app.get('/test', (_req, res) => {
  res.json({ message: 'Backend funcionando correctamente' });
});

// Endpoint para registrar una nueva solicitud de acceso
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const { error } = await supabase
      .from('users')
      .insert([{ email, password_hash: hashedPassword, status: 'pending', access_token: null }])
      .select()
      .single();

    if (error) {
      if ((error as any).code === '23505') {
        return res.status(409).json({ error: 'El email ya está registrado.' });
      }
      throw error;
    }
    res.status(201).json({ message: 'Solicitud de registro enviada. Espera la aprobación del administrador.' });
  } catch (error: any) {
    console.error('Error en el registro:', error.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Endpoint para iniciar sesión
app.post('/login', async (req, res) => {
  const { email, password, access_token } = req.body;
  if (!email || !password || !access_token) {
    return res.status(400).json({ error: 'Email, contraseña y token de acceso son requeridos.' });
  }

  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    if (user.status !== 'approved') {
      return res.status(403).json({ error: 'Tu cuenta no ha sido aprobada o está deshabilitada.' });
    }
    if (user.access_token !== access_token) {
      return res.status(401).json({ error: 'Token de acceso inválido.' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Contraseña incorrecta.' });
    }
    const sessionToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'tu_secreto_jwt_super_secreto',
      { expiresIn: '7d' }
    );
    res.status(200).json({ message: 'Inicio de sesión exitoso', token: sessionToken });
  } catch (error: any) {
    console.error('Error en el inicio de sesión:', error.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.get('/invitation/:urlId', async (req, res) => {
  const { urlId } = req.params;
  try {
    const { data, error } = await supabase.from('invitations').select('*').eq('url_id', urlId).single();
    if (error) {
      return res.status(404).json({ error: 'Invitación no encontrada.' });
    }
    if (!data) {
      return res.status(404).json({ error: 'Invitación no encontrada.' });
    }
    res.status(200).json(data);
  } catch (error: any) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/rsvp', async (req, res) => {
  const { invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending } = req.body;
  if (!invitation_id || !names || !participants_count || !email || (confirmed_attendance === undefined && not_attending === undefined)) {
    return res.status(400).json({ error: 'Faltan campos obligatorios para la confirmación de asistencia.' });
  }

  try {
    const { data, error } = await supabase
      .from('rsvps')
      .insert([{ invitation_id, names, participants_count, email, phone, observations, confirmed_attendance, not_attending }]);
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    res.status(201).json({ message: 'Confirmación de asistencia registrada con éxito.', data });
  } catch (error: any) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.get('/rsvps/:invitationId', async (req, res) => {
  const { invitationId } = req.params;
  try {
    const { data, error } = await supabase.from('rsvps').select('*').eq('invitation_id', invitationId);
    if (error) {
      return res.status(404).json({ error: 'No se encontraron RSVPs para esta invitación.' });
    }
    res.status(200).json(data);
  } catch (error: any) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.get('/rsvps/download/:invitationId', async (req, res) => {
  const { invitationId } = req.params;
  try {
    const { data: rsvps, error } = await supabase.from('rsvps').select('*').eq('invitation_id', invitationId);
    if (error) {
      return res.status(404).json({ error: 'No se encontraron RSVPs para esta invitación.' });
    }

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Invitados');
    worksheet.columns = [
      { header: 'Nombre', key: 'names', width: 30 },
      { header: 'Cantidad de Participantes', key: 'participants_count', width: 25 },
      { header: 'Email', key: 'email', width: 30 },
      { header: 'Teléfono', key: 'phone', width: 20 },
      { header: 'Observaciones', key: 'observations', width: 40 },
      { header: 'Confirmación de Asistencia', key: 'confirmed_attendance', width: 25 },
    ];

    (rsvps || []).forEach((rsvp: Rsvp) => {
      let namesToDisplay = 'N/A';
      if (rsvp.names) {
        if (typeof rsvp.names === 'string') {
          try {
            const parsedNames = JSON.parse(rsvp.names);
            if (Array.isArray(parsedNames)) {
              namesToDisplay = parsedNames.join(', ');
            } else {
              namesToDisplay = rsvp.names;
            }
          } catch (e) {
            namesToDisplay = rsvp.names;
          }
        } else if (Array.isArray(rsvp.names)) {
          namesToDisplay = rsvp.names.join(', ');
        }
      }

      worksheet.addRow({ ...rsvp, names: namesToDisplay });
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=invitados_${invitationId}.xlsx`);
    await workbook.xlsx.write(res);
    res.end();
  } catch (error: any) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Middleware para autenticar el token JWT
const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && (authHeader as string).split(' ')[1];
  if (token == null || typeof token !== 'string') {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.JWT_SECRET as string, (err: any, user: any) => {
    if (err) {
      return res.sendStatus(403);
    }
    (req as any).user = user;
    next();
  });
};

// Ruta protegida de ejemplo
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Acceso a ruta protegida concedido', user: (req as any).user });
});

// Nuevo endpoint para obtener las invitaciones del usuario autenticado
app.get('/my-invitations', authenticateToken, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { data: userData, error: userError } = await supabase.from('users').select('accessible_invitations').eq('id', userId).single();
    if (userError || !userData) {
      return res.status(404).json({ error: 'Datos de usuario no encontrados.' });
    }
    const accessibleInvitationIds = Array.isArray(userData.accessible_invitations) ? userData.accessible_invitations : [];
    if (accessibleInvitationIds.length === 0) {
      return res.status(200).json([]);
    }
    const { data: invitations, error: invitationsError } = await supabase.from('invitations').select('*').in('id', accessibleInvitationIds);
    if (invitationsError) {
      return res.status(500).json({ error: 'Error interno del servidor al obtener invitaciones.' });
    }
    res.status(200).json(invitations);
  } catch (error: any) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Nuevo endpoint para otorgar acceso a invitaciones
app.post('/admin/grant-invitation-access', authenticateToken, async (req, res) => {
  const { targetUserId, invitationId } = req.body;
  if (!targetUserId || !invitationId) {
    return res.status(400).json({ error: 'targetUserId e invitationId son requeridos.' });
  }

  try {
    const requestingUser = (req as any).user.userId;
    const { data: invitation, error: invitationError } = await supabase.from('invitations').select('user_id').eq('id', invitationId).single();
    if (invitationError || !invitation) {
      return res.status(404).json({ error: 'Invitación no encontrada.' });
    }
    if (invitation.user_id !== requestingUser) {
      return res.status(403).json({ error: 'No tienes permiso para modificar esta invitación.' });
    }
    const { data: targetUser, error: targetUserError } = await supabase.from('users').select('accessible_invitations').eq('id', targetUserId).single();
    if (targetUserError || !targetUser) {
      return res.status(404).json({ error: 'Usuario objetivo no encontrado.' });
    }
    const currentAccessibleInvitations = Array.isArray(targetUser.accessible_invitations) ? targetUser.accessible_invitations : [];
    if (!currentAccessibleInvitations.includes(invitationId)) {
      currentAccessibleInvitations.push(invitationId);
    }
    const { error: updateError } = await supabase
      .from('users')
      .update({ accessible_invitations: currentAccessibleInvitations })
      .eq('id', targetUserId);
    if (updateError) {
      console.error('Error al actualizar accessible_invitations:', updateError.message);
      return res.status(500).json({ error: 'Error interno del servidor al otorgar acceso.' });
    }
    res.status(200).json({ message: 'Acceso a la invitación otorgado exitosamente.' });
  } catch (error: any) {
    console.error('Error en /admin/grant-invitation-access:', error.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// 3. Exportación final para Vercel
// Esta línea es crucial para que Vercel encuentre y ejecute la aplicación.
export default serverless(app);

