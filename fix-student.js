const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function fixStudent() {
  const email = 'student@school.com';
  const password = 'Student123!';
  const hash = await bcrypt.hash(password, 12);

  const existing = await prisma.user.findUnique({ where: { email } });
  
  if (existing) {
    // Update existing user
    await prisma.user.update({
      where: { email },
      data: { passwordHash: hash, isActive: true }
    });
    console.log(`✅ Updated password for ${email}`);
  } else {
    // Create new student
    await prisma.user.create({
      data: {
        email,
        passwordHash: hash,
        firstName: 'Test',
        lastName: 'Student',
        studentId: 'STU001',
        department: 'Computer Science',
        isActive: true,
        userRoles: {
          create: {
            role: { connect: { name: 'Student' } }
          }
        }
      }
    });
    console.log(`✅ Created new student: ${email}`);
  }
  await prisma.$disconnect();
}

fixStudent();