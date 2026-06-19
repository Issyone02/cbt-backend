const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function createStudent() {
  const hash = await bcrypt.hash('Student123!', 12);
  const student = await prisma.user.create({
    data: {
      email: 'student@school.com',
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
  console.log('Student created:', student.email, '| Password: Student123!');
}
createStudent().finally(() => prisma.$disconnect());