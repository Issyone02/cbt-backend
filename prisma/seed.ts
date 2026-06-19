import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const roles = ['SuperAdmin', 'SchoolAdmin', 'Lecturer', 'Student', 'Invigilator', 'Support'];
  for (const name of roles) {
    await prisma.role.upsert({
      where: { name },
      update: {},
      create: { name }
    });
  }

  const adminEmail = 'admin@school.com';
  const existing = await prisma.user.findUnique({ where: { email: adminEmail } });
  if (!existing) {
    const hashed = await bcrypt.hash('Admin123!', 12);
    await prisma.user.create({
      data: {
        email: adminEmail,
        passwordHash: hashed,
        firstName: 'System',
        lastName: 'Admin',
        isActive: true,
        userRoles: {
          create: [
            { role: { connect: { name: 'SuperAdmin' } } },
            { role: { connect: { name: 'SchoolAdmin' } } }
          ]
        }
      }
    });
    console.log('Admin created:', adminEmail);
  }
}

main()
  .catch(e => console.error(e))
  .finally(async () => await prisma.$disconnect());