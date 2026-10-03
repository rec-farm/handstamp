import { z } from 'zod';

// A group's slug is what apps see in the `groups` claim, so it is short, stable and boring.
export const GROUP_SLUG = /^[a-z0-9][a-z0-9._:-]{0,63}$/;

export const groupSchema = z.object({
  slug: z
    .string()
    .trim()
    .regex(GROUP_SLUG, 'Use lowercase letters, digits, dots, dashes, colons or underscores.'),
  name: z.string().trim().min(1, 'Give the group a name.').max(80),
  description: z.string().trim().max(280).default(''),
});

export type GroupInput = z.output<typeof groupSchema>;
