import type { ThemePreference } from '../useTheme';

const ORDER: ThemePreference[] = ['system', 'light', 'dark'];
const ICON: Record<ThemePreference, string> = { system: '◐', light: '☀', dark: '☾' };
const LABEL: Record<ThemePreference, string> = { system: 'Theme: system', light: 'Theme: light', dark: 'Theme: dark' };

export function ThemeToggle({ theme, onChange }: { theme: ThemePreference; onChange: (theme: ThemePreference) => void }) {
  function cycle() {
    const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length];
    onChange(next);
  }
  return (
    <button className="icon" onClick={cycle} title={LABEL[theme]} aria-label={LABEL[theme]}>
      {ICON[theme]}
    </button>
  );
}
