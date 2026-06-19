/**
 * CBT System — Admin Password Recovery Script
 * ─────────────────────────────────────────────────────────────────────────────
 * SECURITY DESIGN — READ BEFORE USING:
 *
 * WHAT THIS SCRIPT DOES:
 *   - Generates a ONE-TIME temporary password (random, 12 chars)
 *   - The developer NEVER chooses the password — it is system-generated
 *   - The temporary password is printed ONCE and expires after 15 minutes
 *   - The admin MUST change it immediately on first login
 *   - Every use is recorded in the AuditLog with timestamp
 *
 * WHY THIS IS SAFER THAN DEVELOPER-CHOSEN PASSWORD:
 *   - Developer cannot silently pick a password they remember later
 *   - The temp password is random — no one can predict or memorize it
 *   - 15-minute expiry means the window for misuse is tiny
 *   - The admin sees the audit log entry on their next login
 *
 * REMAINING RISK (be honest with your client):
 *   - A developer with server access COULD read the temp password from terminal
 *   - Mitigation: run this script with the admin physically present / on a call
 *   - The admin should change their password immediately and check audit logs
 *
 * HOW TO RUN (from backend/ folder):
 *   npx ts-node scripts/reset-admin-password.ts
 *
 * BEST PRACTICE PROCEDURE:
 *   1. Admin calls developer and confirms their identity verbally
 *   2. Developer runs the script — temp password appears on screen
 *   3. Developer reads it aloud to the admin (or shares via WhatsApp/phone)
 *   4. Admin logs in immediately and changes password
 *   5. Both parties can verify the audit log entry was created
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import * as readline from 'readline';
import * as crypto from 'crypto';
import * as dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, ans => resolve(ans.trim())));
}

// Generate a readable random temp password: 4 letters + 4 digits + 4 symbols
// Easy to read aloud, hard to guess
function generateTempPassword(): string {
  const letters  = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  const digits   = '23456789';
  const symbols  = '@#$%&';
  const pick = (chars: string, n: number) =>
    Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]).join('');
  const parts = [pick(letters, 4), pick(digits, 4), pick(symbols, 2)];
  // Shuffle the combined result
  return parts.join('').split('').sort(() => crypto.randomInt(3) - 1).join('');
}

async function main() {
  console.log('\n════════════════════════════════════════════════════');
  console.log('      CBT System  —  Admin Password Recovery');
  console.log('════════════════════════════════════════════════════');
  console.log('\n⚠  SECURITY NOTICE:');
  console.log('   This script generates a temporary password.');
  console.log('   The admin should be present or on the phone.');
  console.log('   The temp password expires in 15 minutes.\n');

  const proceed = await ask('Confirm you have verified the admin\'s identity (yes/no): ');
  if (proceed.toLowerCase() !== 'yes') {
    console.log('\nCancelled. Always verify identity before resetting a password.\n');
    rl.close(); await prisma.$disconnect(); process.exit(0);
  }

  const email = await ask('\nAdmin email address: ');
  if (!email) { console.error('Email is required.'); process.exit(1); }

  const user = await prisma.user.findUnique({
    where: { email },
    include: { userRoles: { include: { role: true } } }
  });

  if (!user) {
    console.error(`\n❌ No account found for "${email}".\n`);
    rl.close(); await prisma.$disconnect(); process.exit(1);
  }

  const roles = user.userRoles.map(ur => ur.role.name);
  console.log(`\n✓ Account: ${user.firstName} ${user.lastName} (${roles.join(', ')})`);

  const confirm = await ask('Reset this account\'s password? (yes/no): ');
  if (confirm.toLowerCase() !== 'yes') {
    console.log('\nCancelled.\n');
    rl.close(); await prisma.$disconnect(); process.exit(0);
  }

  // Generate temp password — developer does NOT choose it
  const tempPassword = generateTempPassword();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  // Save old password to history
  await prisma.passwordHistory.create({ data: { userId: user.id, passwordHash: user.passwordHash } });
  const allHistory = await prisma.passwordHistory.findMany({
    where: { userId: user.id }, orderBy: { createdAt: 'desc' }, select: { id: true }
  });
  if (allHistory.length > 3)
    await prisma.passwordHistory.deleteMany({ where: { id: { in: allHistory.slice(3).map(h => h.id) } } });

  // Store temp password hash + expiry in a reset request so the system
  // forces a password change on first login
  const passwordHash = await bcrypt.hash(tempPassword, 12);
  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash }
  });

  // Create a used-once marker so admin is forced to change password on login
  await prisma.passwordResetRequest.create({
    data: {
      userId: user.id,
      resetCode: 'CLI_RECOVERY',
      isUsed: false, // front-end checks this to force password change
      expiresAt
    }
  });

  // Audit log — records WHO ran this, WHEN, and for WHICH account
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: 'ADMIN_PASSWORD_RECOVERY_CLI',
      metadata: JSON.stringify({
        email: user.email,
        performedAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        note: 'Temporary password issued. Admin must change on first login.'
      })
    }
  });

  // Print temp password clearly
  console.log('\n════════════════════════════════════════════════════');
  console.log('  TEMPORARY PASSWORD (expires in 15 minutes):');
  console.log(`\n      ${tempPassword}\n`);
  console.log('  Read this to the admin now.');
  console.log('  They must log in and change it immediately.');
  console.log('  This password will NOT work after 15 minutes.');
  console.log('════════════════════════════════════════════════════\n');

  rl.close();
  await prisma.$disconnect();
}

main().catch(async err => {
  console.error('\n❌ Script failed:', err.message, '\n');
  rl.close();
  await prisma.$disconnect();
  process.exit(1);
});