// RootSystems social profiles, shown as icon links in the footer. This list is the one place to change them:
// to add LinkedIn later, add { name: 'LinkedIn', url: 'https://www.linkedin.com/company/...', icon: 'linkedin' }.
export const SOCIAL_LINKS: ReadonlyArray<{ name: string; url: string; icon: keyof typeof ICONS }> = [
  { name: 'X', url: 'https://x.com/TheROOTsystems', icon: 'x' },
  { name: 'Instagram', url: 'https://www.instagram.com/therootsystemms/', icon: 'instagram' }
];

const ICONS = {
  x: <path fill="currentColor" d="M18.9 1.15h3.68l-8.04 9.19L24 22.85h-7.4l-5.8-7.58-6.64 7.58H.47l8.6-9.83L0 1.15h7.6l5.24 6.93zM17.6 20.64h2.04L6.48 3.24H4.3z" />,
  instagram: (
    <>
      <g fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="20" rx="5" /><circle cx="12" cy="12" r="4.2" /></g>
      <circle cx="17.6" cy="6.4" r="1.3" fill="currentColor" />
    </>
  ),
  linkedin: <path fill="currentColor" d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z" />
};

export function AppFooter() {
  return (
    <footer className="muted small" style={{ textAlign: 'center', padding: '24px 16px', display: 'flex', gap: 12, justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
      <span>PQC Forge, a RootSystems product</span>
      <a href="https://rootsystems.app/contact?topic=PQC%20Forge" target="_blank" rel="noopener">Contact</a>
      {SOCIAL_LINKS.map((l) => (
        <a key={l.url} href={l.url} target="_blank" rel="noopener" aria-label={`RootSystems on ${l.name}`} title={l.name} style={{ display: 'inline-flex', color: 'inherit' }}>
          <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{ICONS[l.icon]}</svg>
        </a>
      ))}
    </footer>
  );
}
