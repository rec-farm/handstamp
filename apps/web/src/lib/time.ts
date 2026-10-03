const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];
const format = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

// "3 days ago", with the exact ISO time for a tooltip (§12.3).
export function relative(iso: string | null | undefined) {
  if (!iso) return 'never';
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [unit, size] of UNITS)
    if (Math.abs(seconds) >= size) return format.format(Math.round(seconds / size), unit);
  return 'just now';
}
