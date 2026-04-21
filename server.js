
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const OTP_TTL_MS = 10 * 60 * 1000;
const forgotPasswordOtpStore = new Map();

const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpUser = process.env.SMTP_USER || process.env.EMAIL_USER;
const smtpPass = process.env.SMTP_PASS || process.env.EMAIL_PASS;
const smtpFrom = process.env.SMTP_FROM || smtpUser || 'no-reply@poultrysuite.local';

const transporter = (smtpUser && smtpPass)
    ? nodemailer.createTransport(
        smtpHost
            ? {
                host: smtpHost,
                port: smtpPort,
                secure: smtpPort === 465,
                auth: { user: smtpUser, pass: smtpPass }
            }
            : {
                service: 'gmail',
                auth: { user: smtpUser, pass: smtpPass }
            }
    )
    : null;

if (!transporter) {
    console.warn('SMTP not configured. OTP emails will not be delivered; OTP will be logged in backend console.');
}

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const createEstimatedDeliveryDate = (baseDate = new Date()) => {
    const deliveryOffsetDays = Math.floor(Math.random() * 4) + 2;
    const dueDate = new Date(baseDate);
    dueDate.setDate(dueDate.getDate() + deliveryOffsetDays);
    dueDate.setHours(18, 0, 0, 0);
    return dueDate;
};

const sendForgotPasswordOtp = async (email, otp) => {
    if (!transporter) {
        console.log(`[OTP DEV MODE] ${email} -> ${otp}`);
        return false;
    }

    await transporter.sendMail({
        from: smtpFrom,
        to: email,
        subject: 'PoultrySuite Password Reset OTP',
        text: `Your PoultrySuite OTP is ${otp}. It expires in 10 minutes.`,
        html: `<p>Your PoultrySuite OTP is <b>${otp}</b>.</p><p>It expires in 10 minutes.</p>`
    });

    return true;
};

// Serve uploaded assets
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
app.use('/uploads', express.static(uploadsDir));

app.use(cors());
app.use(express.json());

// Serve webapp static files
const webappDir = path.join(__dirname, '..', 'webapp');
if (fs.existsSync(webappDir)) {
    app.use(express.static(webappDir));
    // Serve index.html for the root route
    app.get('/', (req, res) => {
        res.sendFile(path.join(webappDir, 'index.html'));
    });
    console.log('Serving webapp from:', webappDir);
} else {
    console.warn('Webapp directory not found at:', webappDir);
}

// Request Logger
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    if (req.method === 'POST' || req.method === 'PUT') {
        console.log('Body:', req.body);
    }
    next();
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Seed Admin User
const seedAdminUser = async () => {
    try {
        const adminEmail = 'admin@gmail.com';
        const existingAdmin = await prisma.user.findUnique({ where: { email: adminEmail } });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('Admin', 10);
            await prisma.user.create({
                data: {
                    email: adminEmail,
                    password: hashedPassword,
                    role: 'ADMIN',
                    name: 'System Admin'
                }
            });
            console.log('Default Admin user created: admin@gmail.com / Admin');
        } else {
            console.log('Admin user already exists.');
        }
    } catch (e) {
        console.error('Error seeding admin user:', e);
    }
};

// --- AUTH ROUTES ---

app.post('/auth/register', async (req, res) => {
    const { email, password, role, name, phone } = req.body;
    const safeEmail = (email || '').toString().trim().toLowerCase();
    if (!safeEmail || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email: safeEmail,
                password: hashedPassword,
                role: role || 'FARMER',
                name: name || '',
                phone: phone || ''
            },
        });

        // Create Farm if user is Farmer
        if (user.role === 'FARMER') {
            await prisma.farm.create({
                data: {
                    name: `${name || 'New'}'s Farm`,
                    ownerId: user.id
                }
            });
        }

        // Return a token immediately so the app can auto-login after registering
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
        res.json({ message: 'User created successfully', userId: user.id, token, role: user.role, name: user.name });
    } catch (error) {
        res.status(400).json({ error: 'Email already exists or invalid data', details: error.message });
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const safeEmail = (email || '').toString().trim().toLowerCase();
    if (!safeEmail || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    try {
        const user = await prisma.user.findUnique({ where: { email: safeEmail } });
        if (!user) return res.status(400).json({ error: 'User not found' });

        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
            res.json({ token, role: user.role, userId: user.id, name: user.name });
        } else {
            res.status(401).json({ error: 'Invalid password' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/auth/forgot-password/request-otp', async (req, res) => {
    const { email } = req.body;
    const safeEmail = (email || '').toString().trim().toLowerCase();

    if (!safeEmail) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const user = await prisma.user.findUnique({ where: { email: safeEmail } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const otp = generateOtp();
        forgotPasswordOtpStore.set(safeEmail, {
            otp,
            expiresAt: Date.now() + OTP_TTL_MS
        });

        const delivered = await sendForgotPasswordOtp(safeEmail, otp);
        if (delivered) {
            return res.json({ message: 'OTP sent to your email' });
        }

        return res.json({ message: 'OTP generated. Email service not configured; check backend logs.' });
    } catch (error) {
        console.error('Forgot password OTP request error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/auth/forgot-password/verify-otp', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const safeEmail = (email || '').toString().trim().toLowerCase();
    const safeOtp = (otp || '').toString().trim();
    const safePassword = (newPassword || '').toString();

    if (!safeEmail || !safeOtp || !safePassword) {
        return res.status(400).json({ error: 'Email, OTP and new password are required' });
    }

    if (safePassword.length < 5) {
        return res.status(400).json({ error: 'Password must be at least 5 characters' });
    }

    try {
        const user = await prisma.user.findUnique({ where: { email: safeEmail } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const entry = forgotPasswordOtpStore.get(safeEmail);
        if (!entry) {
            return res.status(400).json({ error: 'OTP not found. Please request a new OTP.' });
        }

        if (Date.now() > entry.expiresAt) {
            forgotPasswordOtpStore.delete(safeEmail);
            return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
        }

        if (entry.otp !== safeOtp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        const hashedPassword = await bcrypt.hash(safePassword, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: { password: hashedPassword }
        });

        forgotPasswordOtpStore.delete(safeEmail);
        res.json({ message: 'Password reset successful. Please login with your new password.' });
    } catch (error) {
        console.error('Forgot password OTP verify error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/auth/forgot-password', async (_req, res) => {
    return res.status(400).json({ error: 'Use OTP flow: request-otp then verify-otp' });
});

app.post('/auth/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const safeCurrent = (currentPassword || '').toString();
    const safeNew = (newPassword || '').toString();

    if (!safeCurrent || !safeNew) {
        return res.status(400).json({ error: 'Current password and new password are required' });
    }

    if (safeNew.length < 5) {
        return res.status(400).json({ error: 'New password must be at least 5 characters' });
    }

    try {
        const userId = parseInt(req.user.id);
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isCurrentValid = await bcrypt.compare(safeCurrent, user.password);
        if (!isCurrentValid) {
            return res.status(400).json({ error: 'Current password is invalid' });
        }

        const isSamePassword = await bcrypt.compare(safeNew, user.password);
        if (isSamePassword) {
            return res.status(400).json({ error: 'New password must be different from current password' });
        }

        const hashedPassword = await bcrypt.hash(safeNew, 10);
        await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword }
        });

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Change password error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get current user details
app.get('/auth/me', authenticateToken, async (req, res) => {
    console.log(`[/auth/me] Fetching profile for userId: ${req.user.id}`);
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: {
                id: true,
                email: true,
                name: true,
                phone: true,
                role: true
            }
        });
        if (!user) {
            console.log(`[/auth/me] User not found in database for ID: ${req.user.id}`);
            return res.status(401).json({ error: 'Session invalid: User not found' });
        }
        console.log(`[/auth/me] Profile found: ${user.email}`);
        res.json(user);
    } catch (error) {
        console.error(`[/auth/me] Error:`, error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update current user profile
app.put('/auth/profile', authenticateToken, async (req, res) => {
    const { name, phone } = req.body;
    console.log(`[/auth/profile] Updating profile for userId: ${req.user.id}`);
    try {
        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: {
                name: name,
                phone: phone
            },
            select: {
                id: true,
                email: true,
                name: true,
                phone: true,
                role: true
            }
        });
        console.log(`[/auth/profile] Profile updated successfully for: ${updatedUser.email}`);
        res.json(updatedUser);
    } catch (error) {
        console.error(`[/auth/profile] Error:`, error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- FARMER ROUTES ---

// Helper to get start and end of dates
const startOfToday = new Date();
startOfToday.setHours(0, 0, 0, 0);

const startOfYesterday = new Date(startOfToday);
startOfYesterday.setDate(startOfYesterday.getDate() - 1);

const startOfWeek = new Date(startOfToday);
startOfWeek.setDate(startOfWeek.getDate() - 7);

const startOfMonth = new Date(startOfToday);
startOfMonth.setDate(startOfMonth.getDate() - 30);

// Get Farm Dashboard Data
app.get('/farm/dashboard', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);

    try {
        const farm = await prisma.farm.findUnique({
            where: { ownerId: req.user.id },
            include: {
                batches: true,
                inventory: true,
                products: {
                    include: { order: true }
                }
            }
        });

        if (!farm) return res.status(404).json({ error: "Farm not found" });

        // 1. Total Birds (exclude eggs batches)
        const totalBirds = farm.batches
            .filter(b => b.type !== 'EGGS')
            .reduce((sum, b) => sum + b.count, 0);
        const totalMortality = farm.batches
            .filter(b => b.type !== 'EGGS')
            .reduce((sum, b) => sum + b.mortality, 0);
        const birdsTrend = totalBirds > 0 ? -((totalMortality / totalBirds) * 100) : 0;

        // 1.1 Egg Inventory (EGGS batches)
        const eggStock = farm.batches
            .filter(b => b.type === 'EGGS')
            .reduce((sum, b) => sum + b.count, 0);

        // 2. Eggs Today (Prefer layer-based production; fallback to current eggs inventory when no mature layer batches)
        const activeLayers = farm.batches.filter(b => b.type === 'LAYER' && b.ageDays > 120)
            .reduce((sum, b) => sum + b.count, 0);
        let eggsToday = Math.floor(activeLayers * 0.85); // 85% laying rate
        if (eggsToday === 0) {
            // fallback to eggs inventory if layers are not yet mature or no layer batches exist
            eggsToday = eggStock;
        }

        // Eggs Trend (Based on whether new layers reached maturity this week)
        const newlyMatureLayers = farm.batches.filter(b => b.type === 'LAYER' && b.ageDays >= 120 && b.ageDays < 127)
            .reduce((sum, b) => sum + b.count, 0);
        const eggsTrend = activeLayers > 0 ? (newlyMatureLayers / activeLayers) * 100 : 0;

        // 3. Feed Remaining
        const feedRemaining = farm.inventory ? farm.inventory.feedKg : 0;
        // Feed Trend (Mock calculation based on average daily consumption: 0.12kg per bird)
        const dailyFeedConsumption = totalBirds * 0.12;
        const feedTrend = feedRemaining > 0 ? -((dailyFeedConsumption / feedRemaining) * 100) : 0;

        // 4. Revenue (Using completed Orders)
        const completedOrders = farm.products
            .map(p => p.order)
            .filter(o => o && o.status === 'COMPLETED');

        const todayRevenue = completedOrders
            .filter(o => new Date(o.createdAt) >= startOfToday)
            .reduce((sum, o) => sum + o.totalPrice, 0);

        const yesterdayRevenue = completedOrders
            .filter(o => new Date(o.createdAt) >= startOfYesterday && new Date(o.createdAt) < startOfToday)
            .reduce((sum, o) => sum + o.totalPrice, 0);

        let revenueTrend = 0;
        if (yesterdayRevenue > 0) {
            revenueTrend = ((todayRevenue - yesterdayRevenue) / yesterdayRevenue) * 100;
        } else if (todayRevenue > 0) {
            revenueTrend = 100; // 100% gain if yesterday was 0
        }

        // Charts: Weekly Production (last 7 days — sum of quantities sold per day)
        const weeklyProductionValues = [];
        for (let i = 6; i >= 0; i--) {
            const dayStart = new Date(startOfToday);
            dayStart.setDate(dayStart.getDate() - i);
            const dayEnd = new Date(dayStart);
            dayEnd.setDate(dayEnd.getDate() + 1);

            const daySales = completedOrders
                .filter(o => {
                    const d = new Date(o.createdAt);
                    return d >= dayStart && d < dayEnd;
                });

            // Sum quantities from associated products
            const dayQty = daySales.reduce((sum, o) => {
                const prod = farm.products.find(p => p.order && p.order.id === o.id);
                return sum + (prod ? prod.quantity : 0);
            }, 0);
            weeklyProductionValues.push(dayQty);
        }

        // Charts: Monthly Revenue (last 6 months — sum of completed order value per month)
        const monthlyRevenueValues = [];
        for (let i = 5; i >= 0; i--) {
            const monthStart = new Date();
            monthStart.setDate(1);
            monthStart.setHours(0, 0, 0, 0);
            monthStart.setMonth(monthStart.getMonth() - i);

            const monthEnd = new Date(monthStart);
            monthEnd.setMonth(monthEnd.getMonth() + 1);

            const monthRevenue = completedOrders
                .filter(o => {
                    const d = new Date(o.createdAt);
                    return d >= monthStart && d < monthEnd;
                })
                .reduce((sum, o) => sum + o.totalPrice, 0);
            monthlyRevenueValues.push(monthRevenue);
        }

        res.json({
            ...farm,
            totalBirds,
            eggStock,
            birdsTrend: parseFloat(birdsTrend.toFixed(1)),
            eggsToday,
            eggsTrend: parseFloat(eggsTrend.toFixed(1)),
            feedRemaining,
            feedTrend: parseFloat(feedTrend.toFixed(1)),
            todayRevenue,
            revenueTrend: parseFloat(revenueTrend.toFixed(1)),
            weeklyProductionValues,
            monthlyRevenueValues
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Farmer Profile (Account Screen)
app.get('/farm/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);

    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            include: { farm: true }
        });

        if (!user) return res.status(404).json({ error: 'User not found' });

        const mainFarm = user.farm;

        res.json({
            id: user.id,
            fullName: user.name,
            email: user.email,
            phone: user.phone || 'N/A',
            farmName: mainFarm ? mainFarm.name : 'Unknown Farm',
            location: mainFarm ? (mainFarm.location || 'Unknown Location') : 'Unknown Location',
            farmImages: mainFarm?.images || []
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Upload farm images (Farmer only)
app.post('/farm/profile/images', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const { images } = req.body;

    if (!Array.isArray(images)) {
        return res.status(400).json({ error: 'Invalid images payload; expected array of base64 strings' });
    }

    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const uploadedUrls = [];
        for (let i = 0; i < images.length; i++) {
            const imageData = images[i];
            if (typeof imageData !== 'string' || !imageData.trim()) continue;

            let base64 = imageData;
            let ext = 'jpg';
            const matches = imageData.match(/^data:image\/(png|jpeg|jpg);base64,(.+)$/);
            if (matches) {
                ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
                base64 = matches[2];
            }

            const buffer = Buffer.from(base64, 'base64');
            const fileName = `farm_${farm.id}_${Date.now()}_${i}.${ext}`;
            const filePath = path.join(uploadsDir, fileName);
            fs.writeFileSync(filePath, buffer);

            uploadedUrls.push(`${req.protocol}://${req.get('host')}/uploads/${fileName}`);
        }

        const newImages = [...(farm.images || []), ...uploadedUrls];
        await prisma.farm.update({ where: { id: farm.id }, data: { images: newImages } });

        res.json({ message: 'Farm images uploaded successfully', images: newImages });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Update Farmer Profile (Edit Profile Screen)
app.put('/farm/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const { fullName, phone, farmName, location } = req.body;

    try {
        // Transaction to update both User and Farm
        const updatedData = await prisma.$transaction(async (tx) => {
            // Update User details
            const updatedUser = await tx.user.update({
                where: { id: req.user.id },
                data: {
                    name: fullName,
                    phone: phone
                }
            });

            // Find primary farm
            const userFarm = await tx.farm.findUnique({ where: { ownerId: req.user.id } });
            if (userFarm) {
                // Update Farm details
                await tx.farm.update({
                    where: { id: userFarm.id },
                    data: {
                        name: farmName,
                        location: location
                    }
                });
            }
            return updatedUser;
        });

        res.json({ message: "Profile updated successfully", user: updatedData.id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Batch
app.post('/farm/batch', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.status(403).json({ error: 'Only farmers can add batches' });

    const { type, count, ageDays, startedAt } = req.body;

    if (!type || !count) {
        return res.status(400).json({ error: 'Batch type and count are required' });
    }

    const normalizedType = type.toString().trim().toUpperCase();
    const allowedTypes = ['BROILER', 'LAYER', 'DUCK', 'TURKEY', 'EGGS'];
    if (!allowedTypes.includes(normalizedType)) {
        return res.status(400).json({ error: `Invalid batch type (${type}). Must be one of ${allowedTypes.join(', ')}` });
    }

    const parsedCount = parseInt(count, 10);
    if (Number.isNaN(parsedCount) || parsedCount < 0) {
        return res.status(400).json({ error: 'Count must be a non-negative integer' });
    }

    const parsedAgeDays = parseInt(ageDays || '0', 10);
    if (Number.isNaN(parsedAgeDays) || parsedAgeDays < 0) {
        return res.status(400).json({ error: 'ageDays must be a non-negative integer' });
    }

    let parsedStartedAt = undefined;
    if (startedAt) {
        const date = new Date(startedAt);
        if (Number.isNaN(date.getTime())) {
            return res.status(400).json({ error: 'startedAt must be a valid ISO date string' });
        }
        parsedStartedAt = date;
    }

    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) {
            return res.status(404).json({ error: 'Farm not found for current user' });
        }

        const batchData = {
            farmId: farm.id,
            type: normalizedType,
            count: parsedCount,
            ageDays: parsedAgeDays,
            ...(parsedStartedAt ? { startedAt: parsedStartedAt } : {})
        };

        const batch = await prisma.batch.create({
            data: batchData
        });
        res.json(batch);
    } catch (e) {
        console.error('Error creating batch:', e);
        res.status(500).json({ error: e.message });
    }
});

// Get Batch Details by ID
app.get('/farm/batch/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const batch = await prisma.batch.findFirst({
            where: { id: parseInt(req.params.id), farmId: farm.id },
            include: {
                mortalityRecords: { orderBy: { date: 'desc' } },
                vaccinationRecords: { orderBy: { scheduledDate: 'asc' } },
                feedLogs: { orderBy: { date: 'desc' }, take: 7 }
            }
        });

        if (!batch) return res.status(404).json({ error: 'Batch not found' });

        const weeksOld = Math.floor(batch.ageDays / 7);
        const mortalityRate = batch.count > 0 ? ((batch.mortality / (batch.count + batch.mortality)) * 100) : 0;
        const totalFeedKg = batch.feedLogs.reduce((sum, f) => sum + f.amountKg, 0);
        const avgDailyFeedKg = batch.count > 0 ? batch.count * 0.12 : 0;

        res.json({
            id: batch.id,
            name: `${batch.type.charAt(0) + batch.type.slice(1).toLowerCase()}s`,
            type: batch.type,
            count: batch.count,
            ageDays: batch.ageDays,
            weeksOld,
            mortality: batch.mortality,
            mortalityRate: parseFloat(mortalityRate.toFixed(1)),
            startedAt: batch.startedAt,
            mortalityRecords: batch.mortalityRecords.map(m => ({
                id: m.id, count: m.count, cause: m.cause, date: m.date
            })),
            vaccinationRecords: batch.vaccinationRecords.map(v => ({
                id: v.id, name: v.name, scheduledDate: v.scheduledDate, status: v.status
            })),
            feedLogs: batch.feedLogs.map(f => ({
                id: f.id, amountKg: f.amountKg, date: f.date, notes: f.notes
            })),
            totalFeedKg: parseFloat(totalFeedKg.toFixed(1)),
            avgDailyFeedKg: parseFloat(avgDailyFeedKg.toFixed(1))
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Mortality Record
app.post('/farm/batch/:id/mortality', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const batchId = parseInt(req.params.id);
    const { count, cause } = req.body;
    try {
        const batch = await prisma.batch.findUnique({ where: { id: batchId } });
        if (!batch) return res.status(404).json({ error: 'Batch not found' });

        await prisma.$transaction(async (tx) => {
            await tx.mortalityRecord.create({
                data: { batchId, count: parseInt(count), cause }
            });
            await tx.batch.update({
                where: { id: batchId },
                data: {
                    mortality: { increment: parseInt(count) },
                    count: { decrement: parseInt(count) }
                }
            });
        });
        res.json({ message: 'Mortality logged successfully' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Vaccination Record
app.post('/farm/batch/:id/vaccination', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const batchId = parseInt(req.params.id);
    const { name, scheduledDate, status } = req.body;
    try {
        const record = await prisma.vaccinationRecord.create({
            data: {
                batchId,
                name,
                scheduledDate: new Date(scheduledDate),
                status: status || 'Completed'
            }
        });
        res.json({ message: 'Vaccination logged successfully', record });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Feed Log
app.post('/farm/batch/:id/feed', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const batchId = parseInt(req.params.id);
    const { amountKg, notes } = req.body;

    try {
        const batch = await prisma.batch.findUnique({
            where: { id: batchId },
            include: { farm: true }
        });

        if (!batch) {
            return res.status(404).json({ error: 'Batch not found' });
        }

        const log = await prisma.feedLog.create({
            data: {
                batchId,
                amountKg: parseFloat(amountKg),
                notes: notes || ''
            }
        });

        if (batch.farmId) {
            const inventory = await prisma.inventory.findUnique({
                where: { farmId: batch.farmId }
            });

            if (inventory) {
                const newFeedKg = Math.max(inventory.feedKg - parseFloat(amountKg), 0);
                await prisma.inventory.update({
                    where: { id: inventory.id },
                    data: { feedKg: newFeedKg }
                });
            }
        }

        res.json({ message: 'Feed logged successfully', log });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Feed Stock to Farm Inventory
app.post('/farm/inventory/feed', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const parsedAmountKg = parseFloat(req.body.amountKg);

    if (Number.isNaN(parsedAmountKg) || parsedAmountKg <= 0) {
        return res.status(400).json({ error: 'amountKg must be a positive number' });
    }

    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const inventory = await prisma.inventory.upsert({
            where: { farmId: farm.id },
            create: {
                farmId: farm.id,
                feedKg: parsedAmountKg,
                medicineCount: 0
            },
            update: {
                feedKg: { increment: parsedAmountKg }
            }
        });

        res.json({ message: 'Feed stock updated', feedKg: inventory.feedKg });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Medicine Stock to Farm Inventory
app.post('/farm/inventory/medicine', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const parsedCount = parseInt(req.body.count, 10);

    if (Number.isNaN(parsedCount) || parsedCount <= 0) {
        return res.status(400).json({ error: 'count must be a positive integer' });
    }

    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const inventory = await prisma.inventory.upsert({
            where: { farmId: farm.id },
            create: {
                farmId: farm.id,
                feedKg: 0,
                medicineCount: parsedCount
            },
            update: {
                medicineCount: { increment: parsedCount }
            }
        });

        res.json({ message: 'Medicine stock updated', medicineCount: inventory.medicineCount });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Farm Inventory (Batches with status)
app.get('/farm/inventory', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const farm = await prisma.farm.findUnique({
            where: { ownerId: req.user.id },
            include: {
                batches: {
                    orderBy: { startedAt: 'desc' }
                },
                inventory: true,
                products: {
                    where: { status: 'SOLD' },
                    select: { type: true, status: true }
                }
            }
        });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        // Determine batch status: if all of a batch type has been sold out → Sold, else Active
        const soldTypes = farm.products.map(p => p.type);

        const batches = farm.batches.map((b, idx) => {
            const weeksOld = Math.floor(b.ageDays / 7);
            const mortalityRate = b.count > 0 ? ((b.mortality / (b.count + b.mortality)) * 100) : 0;
            const batchStatus = soldTypes.includes(b.type) && b.count === 0 ? 'Sold' : 'Active';

            return {
                id: b.id,
                name: `Batch ${String.fromCharCode(65 + idx)} - ${b.type.charAt(0) + b.type.slice(1).toLowerCase()}s`,
                type: b.type,
                count: b.count,
                ageDays: b.ageDays,
                weeksOld,
                mortalityRate: parseFloat(mortalityRate.toFixed(1)),
                status: batchStatus,
                startedAt: b.startedAt
            };
        });

        res.json({
            batches,
            feedKg: farm.inventory?.feedKg || 0,
            medicineCount: farm.inventory?.medicineCount || 0
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Sale (Farmer records a completed sale)
const normalizeProductType = (type) => {
    if (!type) return null;
    const normalized = type.toString().trim().toUpperCase();
    const typeMap = {
        'BROILER': 'BROILER',
        'BROILERS': 'BROILER',
        'LAYER': 'LAYER',
        'LAYERS': 'LAYER',
        'DUCK': 'DUCK',
        'DUCKS': 'DUCK',
        'TURKEY': 'TURKEY',
        'TURKEYS': 'TURKEY',
        'EGG': 'EGGS',
        'EGGS': 'EGGS',
        'CHICKS': 'BROILER',
        'CHICK': 'BROILER'
    };
    return typeMap[normalized] || null;
};

app.post('/farm/sale', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const { productType, quantity, pricePerUnit, buyerName, notes, paymentStatus } = req.body;
    const rawType = productType || req.body.type;

    if (!rawType || !quantity || !pricePerUnit) {
        return res.status(400).json({ error: 'productType/type, quantity and pricePerUnit are required' });
    }

    const normalizedType = normalizeProductType(rawType);
    const allowedSaleTypes = ['BROILER', 'LAYER', 'DUCK', 'TURKEY', 'EGGS'];
    if (!normalizedType) {
        return res.status(400).json({ error: `Invalid product type (${productType}). Must be one of Broiler, Layer, Duck, Turkey, or Eggs` });
    }

    const saleQuantity = parseInt(quantity, 10);
    if (Number.isNaN(saleQuantity) || saleQuantity <= 0) {
        return res.status(400).json({ error: 'quantity must be a positive integer' });
    }

    try {
        const farm = await prisma.farm.findUnique({
            where: { ownerId: req.user.id },
            include: { batches: true }
        });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const availableCount = farm.batches
            .filter(b => b.type === normalizedType)
            .reduce((sum, b) => sum + b.count, 0);

        if (availableCount < saleQuantity) {
            return res.status(400).json({ error: `You have only ${availableCount} ${normalizedType.toLowerCase()} available` });
        }

        const totalPrice = parseFloat(pricePerUnit) * saleQuantity;

        const result = await prisma.$transaction(async (tx) => {
            const product = await tx.productRequest.create({
                data: {
                    farmId: farm.id,
                    type: normalizedType,
                    quantity: saleQuantity,
                    pricePerUnit: parseFloat(pricePerUnit),
                    status: 'SOLD'
                }
            });

            let remaining = saleQuantity;
            const sortedBatches = farm.batches
                .filter(b => b.type === normalizedType && b.count > 0)
                .sort((a, b) => new Date(a.startedAt) - new Date(b.startedAt));

            for (const batch of sortedBatches) {
                if (remaining <= 0) break;
                const decrementAmount = Math.min(batch.count, remaining);
                await tx.batch.update({
                    where: { id: batch.id },
                    data: { count: { decrement: decrementAmount } }
                });
                remaining -= decrementAmount;
            }

            const order = await tx.order.create({
                data: {
                    customerId: req.user.id,
                    productId: product.id,
                    totalPrice,
                    status: 'COMPLETED',
                    buyerName: buyerName || 'Walk-in Customer',
                    notes: notes || '',
                    paymentStatus: paymentStatus || 'Paid'
                }
            });

            return { product, order, totalPrice };
        });

        // Use a transaction to create product listing + order atomically
        res.json({
            id: result.order.id,
            productType: result.product.type,
            quantity: result.product.quantity,
            pricePerUnit: result.product.pricePerUnit,
            totalPrice: result.totalPrice,
            buyerName: result.order.buyerName,
            notes: result.order.notes,
            paymentStatus: result.order.paymentStatus,
            status: 'COMPLETED',
            message: 'Sale recorded successfully'
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Farm Sales History
app.get('/farm/sales', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const products = await prisma.productRequest.findMany({
            where: { farmId: farm.id, status: 'SOLD' },
            include: { order: true },
            orderBy: { createdAt: 'desc' }
        });

        const sales = products.map(p => {
            const hasOrder = !!p.order;
            const fallbackStatus = hasOrder ? 'Pending' : 'Paid';
            const sale = {
                id: p.order?.id || p.id,
                productType: p.type,
                quantity: p.quantity,
                pricePerUnit: p.pricePerUnit,
                totalPrice: p.order?.totalPrice || (p.quantity * p.pricePerUnit),
                buyerName: p.order?.buyerName || 'Walk-in Customer',
                notes: p.order?.notes || '',
                paymentStatus: p.order?.paymentStatus || fallbackStatus,
                status: p.order?.status || 'SOLD',
                createdAt: p.createdAt
            };
            console.log(`Sale ID: ${sale.id}, Type: ${hasOrder ? 'Marketplace' : 'Direct'}, Payment: ${sale.paymentStatus}`);
            return sale;
        });

        res.json(sales);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Single Sale Detail (Farmer)
app.get('/farm/sale/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const orderId = parseInt(req.params.id);
    try {
        const order = await prisma.order.findUnique({
            where: { id: orderId },
            include: {
                product: true,
                customer: { select: { name: true, phone: true } }
            }
        });

        if (!order) return res.status(404).json({ error: 'Order not found' });

        // Transform into standardized format
        res.json({
            id: order.id,
            productType: order.product.type,
            quantity: order.product.quantity,
            pricePerUnit: order.product.pricePerUnit,
            totalPrice: order.totalPrice,
            buyerName: order.buyerName || order.customer?.name || 'Customer',
            buyerPhone: order.customer?.phone || null,
            buyerType: order.customer ? 'Marketplace User' : 'Walk-in',
            notes: order.notes,
            paymentStatus: order.paymentStatus,
            paymentMethod: 'Other',
            status: order.status,
            createdAt: order.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Mark Sale as Paid
app.patch('/farm/sale/:id/mark-paid', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const orderId = parseInt(req.params.id);
    try {
        await prisma.order.update({
            where: { id: orderId },
            data: {
                paymentStatus: 'Paid',
                status: 'COMPLETED' // Mark order as completed once paid
            }
        });
        res.json({ message: 'Order marked as paid' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Mark Order as Complete (Farmer marks delivery done)
app.patch('/farm/order/:id/complete', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const orderId = parseInt(req.params.id);
    if (isNaN(orderId)) return res.status(400).json({ error: 'Invalid order ID' });
    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        // Verify this order belongs to the farmer's farm
        const order = await prisma.order.findUnique({
            where: { id: orderId },
            include: { product: true }
        });
        if (!order) return res.status(404).json({ error: 'Order not found' });
        if (String(order.product.farmId) !== String(farm.id)) return res.sendStatus(403);

        await prisma.order.update({
            where: { id: orderId },
            data: {
                status: 'COMPLETED',
                paymentStatus: 'Paid'
            }
        });
        res.json({ message: 'Order marked as complete' });
    } catch (e) {
        console.error('Error marking order complete:', e);
        res.status(500).json({ error: e.message });
    }
});

// Add Expense
app.post('/farm/expense', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const { category, amount, date, description } = req.body;
    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const expense = await prisma.expense.create({
            data: {
                farmId: farm.id,
                category,
                amount: parseFloat(amount),
                date: new Date(date),
                description: description || ''
            }
        });
        res.json({ message: 'Expense added successfully', expense });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Farm Analytics
app.get('/farm/analytics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

        // Calculate Monthly Expenses
        const expenses = await prisma.expense.findMany({
            where: {
                farmId: farm.id,
                date: { gte: startOfMonth }
            }
        });
        const totalExpenses = expenses.reduce((sum, e) => sum + e.amount, 0);

        // Group expenses by category
        const expenseBreakdown = {
            Feed: 0,
            Labor: 0,
            Medication: 0,
            Utilities: 0,
            Other: 0
        };
        expenses.forEach(e => {
            if (expenseBreakdown[e.category] !== undefined) {
                expenseBreakdown[e.category] += e.amount;
            } else {
                expenseBreakdown.Other += e.amount;
            }
        });

        // Calculate Monthly Revenue (from completed orders/sales)
        const products = await prisma.productRequest.findMany({
            where: { farmId: farm.id, status: 'SOLD' },
            include: { order: true }
        });

        let totalRevenue = 0;
        // Simplified Revenue trend: array of weekly revenue within this month, Mocking a 5-week array for visual shape
        let revenueTrend = [0, 0, 0, 0, 0];

        products.forEach(p => {
            // Check if sold this month (assuming created or order created this month)
            const saleDate = p.order ? p.order.createdAt : p.createdAt;
            if (saleDate >= startOfMonth) {
                const amount = p.order ? p.order.totalPrice : (p.quantity * p.pricePerUnit);
                totalRevenue += amount;

                // Quick approx logic for week bucket
                const dayOfMonth = saleDate.getDate();
                const weekIndex = Math.min(Math.floor((dayOfMonth - 1) / 7), 4);
                revenueTrend[weekIndex] += amount;
            }
        });

        // Convert Breakdown to array for UI
        const breakdownList = Object.entries(expenseBreakdown)
            .filter(([_, amount]) => amount >= 0) // keep all for UI completeness or filter empty
            .map(([category, amount]) => ({ category, amount }));

        res.json({
            revenue: totalRevenue,
            expenses: totalExpenses,
            netProfit: totalRevenue - totalExpenses,
            expenseBreakdown: breakdownList,
            revenueTrend
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get single sale detail
app.get('/farm/sale/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const orderId = parseInt(req.params.id);
        const order = await prisma.order.findUnique({
            where: { id: orderId },
            include: {
                product: { include: { farm: { include: { owner: true } } } },
                customer: true
            }
        });
        if (!order) return res.status(404).json({ error: 'Order not found' });

        res.json({
            id: order.id,
            productType: order.product.type,
            quantity: order.product.quantity,
            pricePerUnit: order.product.pricePerUnit,
            totalPrice: order.totalPrice,
            buyerName: order.buyerName || order.customer?.name || 'Walk-in Customer',
            notes: order.notes || '',
            paymentStatus: order.paymentStatus || 'Paid',
            status: order.status,
            createdAt: order.createdAt,
            // Customer info fields (from buyer or recorded)
            buyerPhone: null,
            buyerAddress: null,
            buyerType: 'Regular customer',
            paymentMethod: 'Bank Transfer',
            dueDate: order.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Mark sale as paid
app.patch('/farm/sale/:id/mark-paid', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const orderId = parseInt(req.params.id);
        const updated = await prisma.order.update({
            where: { id: orderId },
            data: { paymentStatus: 'Paid' }
        });
        res.json({ id: updated.id, paymentStatus: updated.paymentStatus, message: 'Marked as paid' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Add Listing (Farmer)
app.post('/market/listing', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    const { type, quantity, pricePerUnit } = req.body;
    const rawType = type || req.body.productType;
    const rawPrice = pricePerUnit ?? req.body.price;

    if (!rawType || !quantity || !rawPrice) {
        return res.status(400).json({ error: 'type/productType, quantity, and pricePerUnit are required' });
    }

    const normalizedType = normalizeProductType(rawType);
    console.log(`[Listing] Received: ${type}, Normalized: ${normalizedType}`);
    
    if (!normalizedType) {
        console.log(`[Listing] Error: Invalid product type (${type})`);
        return res.status(400).json({ error: `Invalid product type (${type}). Must be Broilers, Layers, Eggs, Duck, or Turkey` });
    }

    const listingQuantity = parseInt(quantity, 10);
    if (Number.isNaN(listingQuantity) || listingQuantity <= 0) {
        return res.status(400).json({ error: 'quantity must be a positive integer' });
    }

    try {
        const farm = await prisma.farm.findUnique({
            where: { ownerId: req.user.id },
            include: { batches: true }
        });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const availableCount = farm.batches
            .filter(b => b.type === normalizedType)
            .reduce((sum, b) => sum + b.count, 0);

        console.log(`[Listing] Farm: ${farm.id}, Type: ${normalizedType}, Available: ${availableCount}, Requested: ${listingQuantity}`);

        if (availableCount < listingQuantity) {
            const errorMsg = `You have only ${availableCount} ${normalizedType.toLowerCase()} available for listing`;
            console.log(`[Listing] Error: ${errorMsg}`);
            return res.status(400).json({ error: errorMsg });
        }

        const listing = await prisma.productRequest.create({
            data: {
                farmId: farm.id,
                type: normalizedType,
                quantity: listingQuantity,
                pricePerUnit: parseFloat(rawPrice),
                status: 'AVAILABLE'
            }
        });
        res.json(listing);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get All Listings
app.get('/market/listings', async (req, res) => {
    try {
        const listings = await prisma.productRequest.findMany({
            where: { status: 'AVAILABLE' },
            include: { farm: true }
        });
        res.json(listings);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Farmer's Own Listings
app.get('/market/farm-listings', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);
    try {
        const farm = await prisma.farm.findUnique({
            where: { ownerId: req.user.id }
        });
        if (!farm) {
            return res.status(404).json({ error: 'Farm not found' });
        }

        const listings = await prisma.productRequest.findMany({
            where: { farmId: farm.id },
            include: { farm: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(listings);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Place Order
app.post('/market/order', authenticateToken, async (req, res) => {
    const { productId, purchaseType, deliveryAddress, quantity } = req.body;
    try {
        const pId = parseInt(productId, 10);
        const product = await prisma.productRequest.findUnique({
            where: { id: pId },
            include: { farm: true }
        });

        if (!product || product.status !== 'AVAILABLE') {
            return res.status(400).json({ error: 'Product not available' });
        }

        const requestedQuantity = quantity == null
            ? product.quantity
            : parseInt(quantity, 10);

        if (!Number.isInteger(requestedQuantity) || requestedQuantity <= 0) {
            return res.status(400).json({ error: 'Invalid quantity selected' });
        }

        if (requestedQuantity > product.quantity) {
            return res.status(400).json({ error: `Only ${product.quantity} available` });
        }

        // Get customer name for the order record
        const customer = await prisma.user.findUnique({ where: { id: req.user.id } });
        const mode = (typeof purchaseType === 'string' ? purchaseType : 'ONLINE').toUpperCase();
        const isInStore = mode === 'IN_STORE';
        const safeAddress = typeof deliveryAddress === 'string' ? deliveryAddress.trim() : '';
        const modeTag = isInStore ? '[IN_STORE]' : '[ONLINE]';
        const addressTag = !isInStore && safeAddress ? ` [ADDR]${safeAddress}` : '';

        // Transaction to update product status and create order
        const order = await prisma.$transaction(async (tx) => {
            const remainingQuantity = product.quantity - requestedQuantity;

            await tx.productRequest.update({
                where: { id: pId },
                data: {
                    quantity: requestedQuantity,
                    status: 'SOLD'
                }
            });

            if (remainingQuantity > 0) {
                await tx.productRequest.create({
                    data: {
                        farmId: product.farmId,
                        type: product.type,
                        quantity: remainingQuantity,
                        pricePerUnit: product.pricePerUnit,
                        status: 'AVAILABLE'
                    }
                });
            }

            // --- Inventory Deduction (FIFO) ---
            const batches = await tx.batch.findMany({
                where: { farmId: product.farmId, type: product.type },
                orderBy: { startedAt: 'asc' }
            });

            let quantityToDeduct = requestedQuantity;
            for (const batch of batches) {
                if (quantityToDeduct <= 0) break;
                
                const deduction = Math.min(batch.count, quantityToDeduct);
                await tx.batch.update({
                    where: { id: batch.id },
                    data: { count: batch.count - deduction }
                });
                quantityToDeduct -= deduction;
            }
            // ----------------------------------

            return await tx.order.create({
                data: {
                    customerId: req.user.id,
                    productId: pId,
                    totalPrice: product.pricePerUnit * requestedQuantity,
                    status: 'PENDING',
                    buyerName: customer?.name || 'Customer',
                    paymentStatus: 'Pending',
                    dueDate: createEstimatedDeliveryDate(),
                    notes: `${modeTag}${addressTag} Order for ${requestedQuantity} ${product.type}`.trim()
                }
            });
        });

        res.json(order);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get My Orders (Customer)
app.get('/market/my-orders', authenticateToken, async (req, res) => {
    console.log(`[${new Date().toISOString()}] GET /market/my-orders for User ID: ${req.user.id}`);
    try {
        const orders = await prisma.order.findMany({
            where: { customerId: req.user.id },
            include: {
                product: {
                    include: { farm: true }
                },
                review: true
            },
            orderBy: { createdAt: 'desc' }
        });
        console.log(`Found ${orders.length} orders for User ID: ${req.user.id}`);
        res.json(orders.map(({ review, ...order }) => {
            const notes = order.notes || '';
            const isInStore = /\[IN_STORE\]|in-store|in store|pickup/i.test(notes);
            const addrMatch = notes.match(/\[ADDR\]([^\[]+)/i);
            const parsedAddress = addrMatch?.[1]?.trim() || null;

            return {
                ...order,
                purchaseType: isInStore ? 'IN_STORE' : 'ONLINE',
                deliveryAddress: isInStore ? null : parsedAddress,
                dueDate: order.dueDate,
                isReviewed: review !== null
            };
        }));
    } catch (e) {
        console.error('Error fetching orders:', e);
        res.status(500).json({ error: e.message });
    }
});

// --- ADMIN ROUTES ---

// Get All Farms (Admin)
app.get('/admin/farms', async (req, res) => {
    try {
        const farms = await prisma.farm.findMany({
            include: {
                owner: {
                    select: { name: true, email: true }
                },
                batches: true
            }
        });

        // Transform data for UI
        const farmData = farms.map(farm => {
            const totalBirds = farm.batches.reduce((sum, batch) => sum + batch.count, 0);
            let scale = "Small Scale";
            if (totalBirds > 5000) scale = "Large Scale";
            else if (totalBirds > 1000) scale = "Medium Scale";

            return {
                id: farm.id,
                name: farm.name,
                ownerName: farm.owner.name || "Unknown",
                location: farm.location || "Unknown Location",
                totalBirds: totalBirds,
                scale: scale,
                initial: farm.name.charAt(0).toUpperCase()
            };
        });

                dueDate: order.dueDate || createEstimatedDeliveryDate(order.createdAt),
        res.json(farmData);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Get Single Farm Details (Admin)
app.get('/admin/farm/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const farm = await prisma.farm.findUnique({
            where: { id: parseInt(id) },
            include: {
                owner: { select: { name: true, email: true, phone: true, createdAt: true } },
                batches: true,
                inventory: true,
                products: true,
                // In a real app, include orders via products to calc revenue
                // orders: true 
            }
        });

        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        // Calculate Stats
        const totalBirds = farm.batches.reduce((sum, batch) => sum + batch.count, 0);

        // Mocking Monthly Revenue for now as order relation is via ProductRequest
        // In refined schema, we would sum up completed orders for this farm
        const monthlyRevenue = 1250000.0;

        const productsCount = farm.products.filter(p => p.status === 'AVAILABLE').length;

        const productTypes = [...new Set(farm.products.map(p => p.type))];

        const farmDetails = {
            id: farm.id,
            name: farm.name,
            ownerName: farm.owner.name || "Unknown",
            location: farm.location || "Unknown Location",
            phone: farm.owner.phone || "N/A",
            email: farm.owner.email,
            joinedDate: farm.owner.createdAt,
            status: "Active", // Mocked
            scale: totalBirds > 5000 ? "Large Scale" : (totalBirds > 1000 ? "Medium Scale" : "Small Scale"),
            totalBirds: totalBirds,
            monthlyRevenue: monthlyRevenue,
            productsCount: productsCount,
            productTypes: productTypes, // ["BROILER", "EGGS", etc]
            // Mocking Graph Data for "Monthly Production"
            productionGraph: [4500, 5000, 4800, 5200, 5100, 5300]
        };

        res.json(farmDetails);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
app.get('/admin/stats', async (req, res) => {
    try {
        const formatPercent = (current, previous) => {
            if (previous === 0) return current > 0 ? '+100%' : '0%';
            const value = (((current - previous) / previous) * 100).toFixed(0);
            return `${Number(value) >= 0 ? '+' : ''}${value}%`;
        };

        const usersCount = await prisma.user.count();
        const farmsCount = await prisma.farm.count();
        const ordersCount = await prisma.order.count();

        const salesAgg = await prisma.order.aggregate({
            _sum: { totalPrice: true }
        });
        const totalSales = salesAgg._sum.totalPrice || 0;

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const revenueLabels = [];
        const revenueData = [];

        for (let i = 5; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(today.getDate() - i);
            const startOfDay = new Date(date);
            startOfDay.setHours(0, 0, 0, 0);
            const endOfDay = new Date(date);
            endOfDay.setHours(23, 59, 59, 999);

            const dailyOrders = await prisma.order.findMany({
                where: {
                    createdAt: {
                        gte: startOfDay,
                        lte: endOfDay
                    }
                }
            });

            revenueLabels.push(days[date.getDay()]);
            revenueData.push(dailyOrders.reduce((sum, order) => sum + order.totalPrice, 0));
        }

        const pendingOrders = await prisma.order.count({ where: { status: 'PENDING' } });

        const userGrowthLabels = [];
        const userGrowthData = [];
        const userGrowthDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        let usersLast7Days = 0;

        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(today.getDate() - i);
            const start = new Date(date);
            start.setHours(0, 0, 0, 0);
            const end = new Date(date);
            end.setHours(23, 59, 59, 999);

            const dailyUsers = await prisma.user.count({
                where: { createdAt: { gte: start, lte: end } }
            });

            userGrowthLabels.push(userGrowthDays[date.getDay()]);
            userGrowthData.push(dailyUsers);
            usersLast7Days += dailyUsers;
        }

        const prev7Start = new Date(today);
        prev7Start.setDate(prev7Start.getDate() - 14);
        const prev7End = new Date(today);
        prev7End.setDate(prev7End.getDate() - 7);
        prev7End.setHours(23, 59, 59, 999);
        const usersPrev7Days = await prisma.user.count({
            where: { createdAt: { gte: prev7Start, lte: prev7End } }
        });
        const usersPercent = formatPercent(usersLast7Days, usersPrev7Days);

        const highRiskUsers = await prisma.user.count({ where: { status: 'SUSPENDED' } });
        const highRiskPercent = '0%';

        const sevenDaysAgo = new Date(today);
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const recentOrders = await prisma.order.findMany({
            where: { createdAt: { gte: sevenDaysAgo } },
            select: { customerId: true }
        });
        const activeNowSet = new Set(recentOrders.map(o => o.customerId));
        const recentListings = await prisma.productRequest.findMany({
            where: { createdAt: { gte: sevenDaysAgo } },
            include: { farm: true }
        });
        recentListings.forEach(listing => {
            if (listing.farm?.ownerId) {
                activeNowSet.add(listing.farm.ownerId);
            }
        });
        const activeNow = activeNowSet.size;

        const previousActiveStart = new Date(today);
        previousActiveStart.setDate(previousActiveStart.getDate() - 14);
        const previousActiveEnd = new Date(today);
        previousActiveEnd.setDate(previousActiveEnd.getDate() - 8);
        previousActiveEnd.setHours(23, 59, 59, 999);
        const previousOrders = await prisma.order.findMany({
            where: { createdAt: { gte: previousActiveStart, lte: previousActiveEnd } },
            select: { customerId: true }
        });
        const previousActiveSet = new Set(previousOrders.map(order => order.customerId));
        const previousListings = await prisma.productRequest.findMany({
            where: { createdAt: { gte: previousActiveStart, lte: previousActiveEnd } },
            include: { farm: true }
        });
        previousListings.forEach(listing => {
            if (listing.farm?.ownerId) {
                previousActiveSet.add(listing.farm.ownerId);
            }
        });
        const activePercent = formatPercent(activeNow, previousActiveSet.size);

        const tomorrowStart = new Date(today);
        tomorrowStart.setDate(tomorrowStart.getDate() + 1);
        const ordersToday = await prisma.order.count({
            where: { createdAt: { gte: today, lt: tomorrowStart } }
        });
        const listingsToday = await prisma.productRequest.count({
            where: { createdAt: { gte: today, lt: tomorrowStart } }
        });
        const logsCount = ordersToday + listingsToday;
        const logsToday = String(logsCount);

        const yesterdayStart = new Date(today);
        yesterdayStart.setDate(yesterdayStart.getDate() - 1);
        const yesterdayEnd = new Date(today);
        const ordersYesterday = await prisma.order.count({
            where: { createdAt: { gte: yesterdayStart, lt: yesterdayEnd } }
        });
        const listingsYesterday = await prisma.productRequest.count({
            where: { createdAt: { gte: yesterdayStart, lt: yesterdayEnd } }
        });
        const logsPercent = formatPercent(logsCount, ordersYesterday + listingsYesterday);

        res.json({
            users: usersCount,
            farms: farmsCount,
            orders: ordersCount,
            totalSales,
            pendingApprovals: pendingOrders,
            activeNow,
            highRiskUsers,
            logsToday,
            userGrowthData,
            userGrowthLabels,
            revenueData,
            revenueLabels,
            usersPercent,
            highRiskPercent,
            activePercent,
            logsPercent
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Admin Sales Analytics
app.get('/admin/sales', async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // 1. Today's Revenue & Orders
        const todayOrders = await prisma.order.findMany({
            where: {
                createdAt: {
                    gte: today
                }
            }
        });

        const todayRevenue = todayOrders.reduce((sum, order) => sum + order.totalPrice, 0);
        const todayOrdersCount = todayOrders.length;

        // 2. Weekly Revenue (Last 7 Days)
        const weeklyRevenue = [];
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(today.getDate() - i);
            const startOfDay = new Date(date);
            startOfDay.setHours(0, 0, 0, 0);
            const endOfDay = new Date(date);
            endOfDay.setHours(23, 59, 59, 999);

            const dailyOrders = await prisma.order.findMany({
                where: {
                    createdAt: {
                        gte: startOfDay,
                        lte: endOfDay
                    }
                }
            });

            const dailyTotal = dailyOrders.reduce((sum, order) => sum + order.totalPrice, 0);
            weeklyRevenue.push({
                day: days[date.getDay()],
                revenue: dailyTotal
            });
        }

        // 3. Recent Transactions
        const recentTransactions = await prisma.order.findMany({
            take: 10,
            orderBy: { createdAt: 'desc' },
            include: {
                customer: { select: { name: true } },
                product: { include: { farm: { select: { name: true } } } }
            }
        });

        const formattedTransactions = recentTransactions.map(t => ({
            id: t.id,
            customerName: t.customer.name,
            farmName: t.product.farm.name,
            items: `${t.product.quantity} ${t.product.type}`, // e.g., "500 Eggs"
            amount: t.totalPrice,
            status: t.status,
            date: t.createdAt
        }));

        res.json({
            todayRevenue,
            todayOrders: todayOrdersCount,
            weeklyRevenue,
            recentTransactions: formattedTransactions
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Get Single Transaction Details
app.get('/admin/transaction/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const transaction = await prisma.order.findUnique({
            where: { id: id }, // Assuming ID is UUID string, if Int parse it
            include: {
                customer: { select: { name: true, email: true, phone: true } },
                product: {
                    include: {
                        farm: { select: { name: true, location: true } }
                    }
                }
            }
        });

        if (!transaction) return res.status(404).json({ error: 'Transaction not found' });

        res.json({
            id: transaction.id,
            date: transaction.createdAt,
            status: transaction.status,
            amount: transaction.totalPrice,
            customer: {
                name: transaction.customer.name,
                email: transaction.customer.email,
                phone: transaction.customer.phone
            },
            product: {
                name: transaction.product.type,
                quantity: transaction.product.quantity,
                pricePerUnit: transaction.product.pricePerUnit,
                farm: transaction.product.farm.name,
                location: transaction.product.farm.location
            }
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get All Users (Admin)
app.get('/admin/users', async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            orderBy: { createdAt: 'desc' }
        });

        // Transform data for UI
        const userList = users.map(user => {
            // Calculate last active based on last order or just createdAt for now
            // typically you'd track lastLoginAt
            const timeAgo = "Active recently";

            return {
                id: user.id.toString(), // Ensuring it's a string
                name: user.name,
                email: user.email,
                role: user.role,
                status: user.status || "ACTIVE", // Fallback
                lastActive: user.createdAt.toISOString(),
                initial: user.name ? user.name.charAt(0).toUpperCase() : 'U'
            };
        });

        res.json(userList);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get User Details (Admin)
app.get('/admin/user/:id', async (req, res) => {
    const { id } = req.params;
    const userId = parseInt(id);
    try {
        const user = await prisma.user.findUnique({
            where: { id: userId }
        });

        if (!user) return res.status(404).json({ error: 'User not found' });

        // Calculate Stats
        const ordersCount = await prisma.order.count({ where: { customerId: userId } });

        const salesAgg = await prisma.order.aggregate({
            where: { customerId: userId },
            _sum: { totalPrice: true }
        });
        const totalRevenue = salesAgg._sum.totalPrice || 0;

        // Days Active
        const now = new Date();
        const createdDate = new Date(user.createdAt);
        const daysActive = Math.max(1, Math.floor((now - createdDate) / (1000 * 60 * 60 * 24)));

        // Risk Evaluation
        let riskText = "Low";
        let riskColorHex = "#22C55E"; // Green
        if (user.status === "SUSPENDED") {
            riskText = "High";
            riskColorHex = "#EF4444"; // Red
        } else if (user.status === "PENDING") {
            riskText = "Med";
            riskColorHex = "#F59E0B"; // Orange
        }

        // Real Activity Graph (Last 7 Days)
        const activityGraph = [];
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);

        for (let i = 6; i >= 0; i--) {
            const date = new Date(todayStart);
            date.setDate(todayStart.getDate() - i);
            const start = new Date(date);
            const end = new Date(date);
            end.setHours(23, 59, 59, 999);

            const dailyOrders = await prisma.order.count({
                where: { customerId: userId, createdAt: { gte: start, lte: end } }
            });
            let dailyListings = 0;
            if (user.role === 'FARMER') {
                const farm = await prisma.farm.findUnique({ where: { ownerId: userId } });
                if (farm) {
                    dailyListings = await prisma.productRequest.count({
                        where: { farmId: farm.id, createdAt: { gte: start, lte: end } }
                    });
                }
            }
            activityGraph.push(dailyOrders + dailyListings);
        }

        // If the graph is entirely flat (no activity), we'll mock some small variance just so the UI graph isn't a straight line at 0, 
        // OR we can just return it. Returning real data means it might be flat. 
        // Let's actually keep it real: if the array sum is 0, we'll assign [0,0,0,0,0,0,0].

        // Recent Activity (Top 3)
        let rawActivities = [];

        // Fetch Orders
        const recentOrders = await prisma.order.findMany({
            where: { customerId: userId },
            orderBy: { createdAt: 'desc' },
            take: 3
        });

        recentOrders.forEach(o => {
            rawActivities.push({
                title: "Placed Order",
                subtitle: `Amount: $${o.totalPrice}`,
                time: o.createdAt.toISOString(),
                type: "ORDER",
                rawDate: o.createdAt
            });
        });

        // If farmer, fetch Recent Listings
        if (user.role === 'FARMER') {
            const farm = await prisma.farm.findUnique({ where: { ownerId: userId } });
            if (farm) {
                const recentListings = await prisma.productRequest.findMany({
                    where: { farmId: farm.id },
                    orderBy: { createdAt: 'desc' },
                    take: 3
                });
                recentListings.forEach(l => {
                    rawActivities.push({
                        title: "Created Listing",
                        subtitle: `${l.quantity} ${l.type}`,
                        time: l.createdAt.toISOString(),
                        type: "LISTING",
                        rawDate: l.createdAt
                    });
                });
            }
        }

        if (user.status === "SUSPENDED") {
            rawActivities.push({
                title: "System Alert",
                subtitle: "Account Suspended",
                time: user.createdAt.toISOString(),
                type: "ALERT",
                rawDate: new Date() // Pin to top
            });
        }

        rawActivities.sort((a, b) => b.rawDate - a.rawDate);
        const recentActivity = rawActivities.slice(0, 3).map(a => ({
            title: a.title,
            subtitle: a.subtitle,
            time: a.time,
            type: a.type
        }));

        res.json({
            id: user.id.toString(),
            name: user.name,
            email: user.email,
            phone: user.phone || "+234 000 000 0000",
            role: user.role,
            location: "Ibadan, Oyo State",
            joinedDate: user.createdAt,
            status: user.status || "ACTIVE",
            totalOrders: ordersCount,
            totalRevenue: totalRevenue,
            activityGraph: activityGraph,
            daysActive: daysActive,
            riskText: riskText,
            riskColorHex: riskColorHex,
            recentActivity: recentActivity
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Update User Status (Admin)
app.put('/admin/user/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // EXPECTS: "ACTIVE", "SUSPENDED", "PENDING"
    const userId = parseInt(id);

    try {
        const user = await prisma.user.update({
            where: { id: userId },
            data: { status: status }
        });
        res.json(user);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get Admin Reports
app.get('/admin/reports', async (req, res) => {
    try {
        const currentYear = new Date().getFullYear();
        const startOfYear = new Date(currentYear, 0, 1);
        const endOfYear = new Date(currentYear, 11, 31, 23, 59, 59);

        // 1. Sales Report (Monthly transaction volume) - Mocked for now or aggregated
        // Real aggregation would group by month.
        const allOrders = await prisma.order.findMany({
            where: {
                createdAt: {
                    gte: startOfYear,
                    lte: endOfYear
                }
            }
        });

        const monthlySales = Array(12).fill(0);
        allOrders.forEach(order => {
            const month = order.createdAt.getMonth(); // 0-11
            monthlySales[month] += order.totalPrice;
        });

        const totalSalesYTD = monthlySales.reduce((a, b) => a + b, 0);

        // 2. User Growth (New registrations per month)
        const allUsers = await prisma.user.findMany({
            where: {
                createdAt: {
                    gte: startOfYear,
                    lte: endOfYear
                }
            }
        });

        const userGrowth = Array(12).fill(0);
        allUsers.forEach(user => {
            const month = user.createdAt.getMonth();
            userGrowth[month]++;
        });

        const totalUsers = await prisma.user.count();

        // 3. Marketplace Analytics
        const activeListings = await prisma.productRequest.count({ where: { status: 'AVAILABLE' } });

        // Count 'COMPLETED' orders. If none, count all non-pending for demo?
        // Let's stick to 'COMPLETED' and assume some will be marked as such later.
        const completedOrders = await prisma.order.count({ where: { status: 'COMPLETED' } });

        const salesAgg = await prisma.order.aggregate({
            _avg: { totalPrice: true },
            where: { status: 'COMPLETED' }
        });
        const avgOrderValue = salesAgg._avg.totalPrice || 0;

        res.json({
            sales: {
                monthly: monthlySales,
                totalYtd: totalSalesYTD
            },
            userGrowth: {
                monthly: userGrowth,
                totalUsers: totalUsers
            },
            marketplace: {
                activeListings,
                completedOrders,
                avgOrderValue
            }
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// --- REVIEW ROUTES ---

// Submit a Review (Customer only, one review per order)
app.post('/review', authenticateToken, async (req, res) => {
    if (req.user.role !== 'CUSTOMER') return res.sendStatus(403);
    const { orderId, rating, comment, images } = req.body;

    if (!orderId || !rating) {
        return res.status(400).json({ error: 'orderId and rating are required' });
    }
    if (parseInt(rating) < 1 || parseInt(rating) > 5) {
        return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    try {
        const order = await prisma.order.findUnique({
            where: { id: parseInt(orderId) },
            include: { product: true }
        });

        if (!order) return res.status(404).json({ error: 'Order not found' });
        if (order.customerId !== req.user.id) return res.status(403).json({ error: 'Not your order' });
        if (order.status !== 'COMPLETED') return res.status(400).json({ error: 'Order not yet completed' });

        const processedImages = Array.isArray(images) ? images : [];

        const review = await prisma.review.create({
            data: {
                farmId: order.product.farmId,
                customerId: req.user.id,
                orderId: parseInt(orderId),
                rating: parseInt(rating),
                comment: comment || null,
                images: processedImages
            }
        });

        res.json({ message: 'Review submitted successfully', review });
    } catch (e) {
        if (e.code === 'P2002') {
            return res.status(400).json({ error: 'You have already reviewed this order' });
        }
        res.status(500).json({ error: e.message });
    }
});

// Get all reviews for a farm (public)
app.get('/review/farm/:farmId', async (req, res) => {
    try {
        const reviews = await prisma.review.findMany({
            where: { farmId: parseInt(req.params.farmId) },
            include: { customer: { select: { name: true } } },
            orderBy: { createdAt: 'desc' }
        });

        res.json(reviews.map(r => ({
            id: r.id.toString(),
            rating: r.rating,
            comment: r.comment,
            images: r.images || [],
            customerName: r.customer.name || 'Anonymous',
            createdAt: r.createdAt
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get all reviews for the logged-in farmer's farm
app.get('/farm/reviews', authenticateToken, async (req, res) => {
    if (req.user.role !== 'FARMER') return res.sendStatus(403);

    try {
        const farm = await prisma.farm.findUnique({ where: { ownerId: req.user.id } });
        if (!farm) return res.status(404).json({ error: 'Farm not found' });

        const reviews = await prisma.review.findMany({
            where: { farmId: farm.id },
            include: { customer: { select: { name: true } } },
            orderBy: { createdAt: 'desc' }
        });

        res.json(reviews.map(r => ({
            id: r.id.toString(),
            rating: r.rating,
            comment: r.comment,
            images: r.images || [],
            customerName: r.customer.name || 'Anonymous',
            createdAt: r.createdAt
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Check if logged-in customer can review a farm (returns eligible orderId or null)
app.get('/review/can-review/:farmId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'CUSTOMER') return res.sendStatus(403);

    try {
        const completedOrders = await prisma.order.findMany({
            where: {
                customerId: req.user.id,
                status: 'COMPLETED',
                product: { farmId: parseInt(req.params.farmId) }
            },
            select: { id: true }
        });

        if (completedOrders.length === 0) {
            return res.json({ canReview: false, orderId: null });
        }

        const orderIds = completedOrders.map(o => o.id);
        const existingReviews = await prisma.review.findMany({
            where: { orderId: { in: orderIds } },
            select: { orderId: true }
        });

        const reviewedSet = new Set(existingReviews.map(r => r.orderId));
        const unreviewed = completedOrders.find(o => !reviewedSet.has(o.id));

        res.json({
            canReview: !!unreviewed,
            orderId: unreviewed ? unreviewed.id.toString() : null
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ─── Messaging Routes ────────────────────────────────────────────

// GET /messages/conversations  — list all conversations for the logged-in user
app.get('/messages/conversations', authenticateToken, async (req, res) => {
    try {
        const userId = parseInt(req.user.id);
        const isCustomer = req.user.role === 'CUSTOMER';

        let convos;
        if (isCustomer) {
            convos = await prisma.conversation.findMany({
                where: { customerId: userId },
                include: {
                    farm: { select: { id: true, name: true } },
                    messages: {
                        orderBy: { createdAt: 'desc' },
                        take: 1
                    }
                },
                orderBy: { updatedAt: 'desc' }
            });
        } else {
            // Farmer: find convos where farm.ownerId = userId
            convos = await prisma.conversation.findMany({
                where: { farm: { ownerId: userId } },
                include: {
                    customer: { select: { id: true, name: true } },
                    messages: {
                        orderBy: { createdAt: 'desc' },
                        take: 1
                    }
                },
                orderBy: { updatedAt: 'desc' }
            });
        }

        const result = convos.map(c => {
            const lastMsg = c.messages[0] || null;
            const unreadCount = c.messages.filter(m => !m.isRead && m.senderId !== userId).length;
            return {
                id: c.id.toString(),
                farmId: c.farmId.toString(),
                farmName: isCustomer ? c.farm.name : `${c.customer?.name ?? 'Customer'}`,
                otherPartyName: isCustomer ? c.farm.name : (c.customer?.name ?? 'Customer'),
                lastMessage: lastMsg?.content ?? null,
                lastMessageTime: lastMsg?.createdAt ?? null,
                unreadCount: 0 // unread count computed below separately for accuracy
            };
        });

        // Efficient per-conversation unread count
        const convoIds = convos.map(c => c.id);
        const unreadGroups = await prisma.message.groupBy({
            by: ['conversationId'],
            where: { conversationId: { in: convoIds }, isRead: false, NOT: { senderId: userId } },
            _count: { id: true }
        });
        const unreadMap = {};
        unreadGroups.forEach(g => { unreadMap[g.conversationId] = g._count.id; });
        result.forEach(r => { r.unreadCount = unreadMap[parseInt(r.id)] || 0; });

        res.json(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /messages/start/:farmId  — start or get conversation with a farm (customer only)
app.post('/messages/start/:farmId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'CUSTOMER') return res.status(403).json({ error: 'Customers only' });
        const customerId = parseInt(req.user.id);
        const farmId = parseInt(req.params.farmId);

        const convo = await prisma.conversation.upsert({
            where: { farmId_customerId: { farmId, customerId } },
            update: {},
            create: { farmId, customerId },
            include: { farm: { select: { id: true, name: true } } }
        });

        res.json({ id: convo.id.toString(), farmId: convo.farmId.toString(), farmName: convo.farm.name });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /messages/start/order/:orderId  — start or get conversation from an order (farmer only)
app.post('/messages/start/order/:orderId', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'FARMER') return res.status(403).json({ error: 'Farmers only' });

        const farmerId = parseInt(req.user.id);
        const orderId = parseInt(req.params.orderId);
        if (Number.isNaN(orderId)) {
            return res.status(400).json({ error: 'Invalid order id' });
        }

        const order = await prisma.order.findUnique({
            where: { id: orderId },
            include: {
                customer: { select: { id: true, name: true, role: true } },
                product: {
                    select: {
                        farmId: true,
                        farm: { select: { ownerId: true } }
                    }
                }
            }
        });

        if (!order) return res.status(404).json({ error: 'Order not found' });
        if (order.product.farm.ownerId !== farmerId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        if (!order.customer || order.customer.role !== 'CUSTOMER') {
            return res.status(400).json({ error: 'No customer chat available for this order' });
        }

        const convo = await prisma.conversation.upsert({
            where: {
                farmId_customerId: {
                    farmId: order.product.farmId,
                    customerId: order.customerId
                }
            },
            update: { updatedAt: new Date() },
            create: { farmId: order.product.farmId, customerId: order.customerId }
        });

        res.json({
            id: convo.id.toString(),
            partnerName: order.customer.name || order.buyerName || 'Customer'
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// GET /messages/:conversationId  — fetch messages in a conversation
app.get('/messages/:conversationId', authenticateToken, async (req, res) => {
    try {
        const userId = parseInt(req.user.id);
        const conversationId = parseInt(req.params.conversationId);

        const convo = await prisma.conversation.findUnique({ where: { id: conversationId } });
        if (!convo) return res.status(404).json({ error: 'Conversation not found' });

        // Verify user is part of this conversation
        const farm = await prisma.farm.findUnique({ where: { id: convo.farmId } });
        const isMember = convo.customerId === userId || farm?.ownerId === userId;
        if (!isMember) return res.status(403).json({ error: 'Access denied' });

        // Mark messages from the other party as read
        await prisma.message.updateMany({
            where: { conversationId, isRead: false, NOT: { senderId: userId } },
            data: { isRead: true }
        });

        const messages = await prisma.message.findMany({
            where: { conversationId },
            orderBy: { createdAt: 'asc' }
        });

        res.json(messages.map(m => ({
            id: m.id.toString(),
            content: m.content,
            senderId: m.senderId.toString(),
            isMine: m.senderId === userId,
            isRead: m.isRead,
            createdAt: m.createdAt
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /messages/:conversationId  — send a message
app.post('/messages/:conversationId', authenticateToken, async (req, res) => {
    try {
        const userId = parseInt(req.user.id);
        const conversationId = parseInt(req.params.conversationId);
        const { content } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'Message content required' });

        const convo = await prisma.conversation.findUnique({ where: { id: conversationId } });
        if (!convo) return res.status(404).json({ error: 'Conversation not found' });

        const farm = await prisma.farm.findUnique({ where: { id: convo.farmId } });
        const isMember = convo.customerId === userId || farm?.ownerId === userId;
        if (!isMember) return res.status(403).json({ error: 'Access denied' });

        const message = await prisma.message.create({
            data: { conversationId, senderId: userId, content: content.trim() }
        });

        // Update conversation updatedAt
        await prisma.conversation.update({ where: { id: conversationId }, data: { updatedAt: new Date() } });

        res.json({
            id: message.id.toString(),
            content: message.content,
            senderId: message.senderId.toString(),
            isMine: true,
            isRead: false,
            createdAt: message.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Start Server
app.listen(PORT, '0.0.0.0', async () => {
    console.log(`Server running on port ${PORT}`);
    await seedAdminUser();
});
