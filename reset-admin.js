const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function reset() {
  const hash = await bcrypt.hash('Student123!', 12);
  const user = await prisma.user.update({
    where: { email: 'student@school.com' },
    data: { passwordHash: hash }
  });
  console.log(`Password for ${user.email} reset to Student123!`);
}
reset().finally(() => prisma.$disconnect());