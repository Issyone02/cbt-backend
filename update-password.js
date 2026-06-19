const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function updatePassword() {
  try {
    const hash = await bcrypt.hash('Admin123!', 12);
    await prisma.user.update({
      where: { email: 'admin@school.com' },
      data: { passwordHash: hash }
    });
    console.log('✅ Admin password updated to: Admin123!');
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

updatePassword();