/**
 * CBT System — Admin Password Recovery Script
 * ─────────────────────────────────────────────────────────────────────────────
 * USE THIS WHEN: an admin (including the only SuperAdmin) forgets their
 * password and CANNOT log in at all — so the in-app "Edit User" self-change
 * flow and the "Forgot Password" code flow are both unavailable to them,
 * since both require either being logged in or another admin to hand them
 * a reset code.
 *
 * This script runs DIRECTLY against the database (works against Neon Postgres
 * the same way it worked against local SQLite — just point DATABASE_URL in
 * your local .env at the same Neon connection string your deployed backend
 * uses). No web login required at all.
 *
 * HOW TO RUN (from the backend/ folder, on YOUR machine — not on Render):
 *   npx ts-node scripts/reset-admin-password.ts
 *
 * SECURITY DESIGN:
 *   - Generates a random, SYSTEM-CHOSEN temporary password — you (the
 *     developer) never pick or type the new password yourself.
 *   - The temp password is shown ONCE on screen and expires in 15 minutes.
 *   - The admin is FORCED to set a new password on their very next login —
 *     the temp password becomes permanently useless the moment they do.
 *   - Every use is recorded in the AuditLog table (action: 
 *     ADMIN_PASSWORD_RECOVERY_CLI) so there's a record of when this was used.
 *
 * RECOMMENDED PROCEDURE:
 *   1. The admin calls you directly and verbally confirms who they are
 *   2. You run this script with them on the phone/call
 *   3. Read the temporary password to them — don't text/email it if avoidable
 *   4. They log in immediately and are forced to set a permanent new password
 *   5. They can check Admin Dashboard → Audit Log afterwards to confirm only
 *      one recovery event happened, at the expected time
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import * as readline from 'readline';
import * as crypto from 'crypto';
import * as dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, ans => resolve(ans.trim())));
}

// Generates a readable random temp password: letters + digits + symbols.
// Easy to read aloud over the phone, hard to guess.
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
  console.log('\n════════════════════════════════════════════════════');
  console.log('      CBT System  —  Admin Password Recovery');
  console.log('════════════════════════════════════════════════════');
  console.log('\n⚠  SECURITY NOTICE:');
  console.log('   This generates a temporary password — not your real one.');
  console.log('   The admin should be present or on a call with you.');
  console.log('   The temp password expires in 15 minutes.\n');

  const proceed = await ask("Confirm you have verified the admin's identity (yes/no): ");
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

  const confirm = await ask("Reset this account's password? (yes/no): ");
  if (confirm.toLowerCase() !== 'yes') {
    console.log('\nCancelled.\n');
    rl.close(); await prisma.$disconnect(); process.exit(0);
  }

  // Generate temp password — the developer does NOT choose it.
  const tempPassword = generateTempPassword();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  // Save current (forgotten) password hash to history before overwriting,
  // keeping only the last 3 — same rule enforced everywhere else in the app.
  await prisma.passwordHistory.create({ data: { userId: user.id, passwordHash: user.passwordHash } });
  const allHistory = await prisma.passwordHistory.findMany({
    where: { userId: user.id }, orderBy: { createdAt: 'desc' }, select: { id: true }
  });
  if (allHistory.length > 3) {
    await prisma.passwordHistory.deleteMany({ where: { id: { in: allHistory.slice(3).map(h => h.id) } } });
  }

  const passwordHash = await bcrypt.hash(tempPassword, 12);
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash } });

  // Mark a CLI_RECOVERY reset request — the login route checks for this and
  // sets mustChangePassword: true, which forces the frontend to show the
  // mandatory "Change Your Password" screen before the dashboard loads.
  await prisma.passwordResetRequest.create({
    data: {
      userId: user.id,
      resetCode: 'CLI_RECOVERY',
      isUsed: false,
      expiresAt
    }
  });

  // Audit log — records WHO this was for, WHEN, and that it was a CLI recovery
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: 'ADMIN_PASSWORD_RECOVERY_CLI',
      metadata: JSON.stringify({
        email: user.email,
        performedAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString()
      })
    }
  });

  console.log('\n════════════════════════════════════════════════════');
  console.log('  TEMPORARY PASSWORD (expires in 15 minutes):');
  console.log(`\n      ${tempPassword}\n`);
  console.log('  Read this to the admin now.');
  console.log('  They will be forced to set a new password on login.');
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
