const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function check() {
  const user = await prisma.user.findUnique({
    where: { email: 'admin@school.com' }
  });
  if (!user) {
    console.log('❌ Admin user not found!');
    return;
  }
  console.log('User found:', user.email);
  console.log('Stored hash:', user.passwordHash);
  const isValid = await bcrypt.compare('Admin123!', user.passwordHash);
  console.log('Password "Admin123!" matches?', isValid);
  await prisma.$disconnect();
}
check();