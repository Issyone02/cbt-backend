/**
 * CBT System — Database Seed Script
 * ─────────────────────────────────────────────────────────────────────────
 * Run once against a fresh database (e.g. right after your first migration)
 * to create:
 *   1. The four system roles: SuperAdmin, SchoolAdmin, Lecturer, Student
 *   2. One initial SuperAdmin account so you can log in for the first time
 *
 * Safe to re-run — if the admin account already exists, it does nothing
 * rather than creating a duplicate or overwriting the password.
 *
 * HOW TO RUN (from the backend/ folder):
 *   npx prisma db seed
 *
 * The temporary password is randomly generated and printed ONCE to the
 * console — it is never hardcoded in this file, so it's safe to commit
 * this script to GitHub without leaking real credentials.
 * ─────────────────────────────────────────────────────────────────────────
 */

import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import * as crypto from 'crypto';

const prisma = new PrismaClient();

// Change this if you want a different first-admin email.
const ADMIN_EMAIL = 'admin@grandissyone.com';

// Same readable random-password generator used by scripts/reset-admin-password.ts
function generateTempPassword(): string {
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  const digits  = '23456789';
  const symbols = '@#$%&';
  const pick = (chars: string, n: number) =>
    Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]).join('');
  const parts = [pick(letters, 4), pick(digits, 4), pick(symbols, 2)];
  return parts.join('').split('').sort(() => crypto.randomInt(3) - 1).join('');
}

async function main() {
  console.log('\n=== CBT System — Database Seed ===\n');

  // 1. Create the four system roles (idempotent — upsert is safe to re-run)
  const roleNames = ['SuperAdmin', 'SchoolAdmin', 'Lecturer', 'Student'];
  for (const name of roleNames) {
    await prisma.role.upsert({ where: { name }, update: {}, create: { name } });
  }
  console.log('✓ Roles ready:', roleNames.join(', '));

  // 2. Create the first SuperAdmin — only if one doesn't already exist
  const existing = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } });

  if (existing) {
    console.log(`\n✓ Admin account already exists: ${ADMIN_EMAIL}`);
    console.log('  No new account created. Use "Forgot Password" or the CLI');
    console.log('  recovery script if you need to reset its password.\n');
    return;
  }

  const tempPassword = generateTempPassword();
  const passwordHash = await bcrypt.hash(tempPassword, 12);

  const superAdminRole = await prisma.role.findUnique({ where: { name: 'SuperAdmin' } });
  if (!superAdminRole) throw new Error('SuperAdmin role was not created — check role upsert above.');

  const user = await prisma.user.create({
    data: {
      email: ADMIN_EMAIL,
      passwordHash,
      firstName: 'Grand',
      lastName: 'Admin',
      isActive: true,
      userRoles: { create: { roleId: superAdminRole.id } }
    }
  });

  console.log('\n========================================');
  console.log('   FIRST SUPERADMIN ACCOUNT CREATED');
  console.log('========================================');
  console.log(`   Email:    ${user.email}`);
  console.log(`   Password: ${tempPassword}`);
  console.log('========================================');
  console.log('   Log in immediately and change this');
  console.log('   password — it will NOT be shown again.');
  console.log('========================================\n');
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
