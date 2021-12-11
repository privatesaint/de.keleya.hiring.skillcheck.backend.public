import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../src/common/utils/password';

const prisma = new PrismaClient();

async function main() {
  await prisma.credentials.deleteMany();
  await prisma.user.deleteMany();

  const hashedPassword = await hashPassword('password');
  let users = [
    {
      name: 'System Admin',
      email: 'admin@test.co',
      email_confirmed: true,
      is_admin: true,

      credentials: {
        create: {
          hash: hashedPassword,
        },
      },
    },
    {
      name: 'John doe',
      email: 'john@test.co',
      email_confirmed: true,
      is_admin: false,

      credentials: {
        create: {
          hash: hashedPassword,
        },
      },
    },
  ];

  await Promise.all(
    users.map(async (user) => {
      await prisma.user.create({
        data: user,
      });
    }),
  );
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
