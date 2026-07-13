import type { CSSProperties } from 'react';
import './protean-font.css';

// Techno wordmark for the "Protean" brand -- a polished-steel gradient-clipped
// text effect (animated: the highlight band sweeps back and forth, like
// light playing across brushed metal) over "Zenter SP" (see protean-font.css
// for the @font-face, the shine keyframes, and the font's license note; only
// the Black/900 demo weight is available, hence font-weight 900 everywhere
// below). Falls back to a monospace chain if the font somehow fails to load.
const FONT_STACK = "'Zenter SP', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

const STEEL_GRADIENT =
  'linear-gradient(110deg, #52565d 0%, #cfd2d6 18%, #ffffff 32%, #7a7e85 46%, #e7e9eb 60%, #45484e 75%, #b7bac0 88%, #52565d 100%)';

const SIZE_PRESETS = {
  // Login screens (admin + portal): large centered wordmark.
  xl: { fontSize: 40, letterSpacing: '0.14em' },
  // Admin sidebar header -- ~50% bigger than the old 15px "Control Panel VPN" label.
  lg: { fontSize: 23, letterSpacing: '0.1em' },
  // Account page ("там данных мало" -- can afford to go big).
  md: { fontSize: 30, letterSpacing: '0.12em' },
  // Portal corner stamp -- small, unobtrusive mark.
  stamp: { fontSize: 12, letterSpacing: '0.08em' },
} as const;

export type ProteanBrandSize = keyof typeof SIZE_PRESETS;

export function ProteanBrand({
  size = 'md', style, children = 'Protean',
}: { size?: ProteanBrandSize; style?: CSSProperties; children?: string }) {
  const preset = SIZE_PRESETS[size];
  return (
    <span
      className="protean-steel"
      style={{
        fontFamily: FONT_STACK,
        fontWeight: 900,
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
        backgroundImage: STEEL_GRADIENT,
        backgroundSize: '250% 100%',
        WebkitBackgroundClip: 'text',
        backgroundClip: 'text',
        color: 'transparent',
        textShadow: '0 1px 0 rgba(255,255,255,.35), 0 -1px 0 rgba(0,0,0,.35)',
        ...preset,
        ...style,
      }}
    >
      {children}
    </span>
  );
}

// Project "stamp" -- either a small rotated corner badge (portal screens:
// present but deliberately unobtrusive) or, with horizontal=true, an inline
// mark meant to sit next to a page title (admin panel page headers) at the
// SAME font-size as that title, passed in via fontSize. Rendered as a
// bordered chip either way, so it reads as a mark/seal rather than
// competing with the page's real content.
export function ProteanStamp({
  style, horizontal, fontSize,
}: { style?: CSSProperties; horizontal?: boolean; fontSize?: number }) {
  return (
    <div
      style={
        horizontal
          ? {
              display: 'inline-flex', alignItems: 'center',
              padding: '2px 12px', border: '1px solid rgba(122,126,133,.4)', borderRadius: 4,
              opacity: 0.8, pointerEvents: 'none', flexShrink: 0,
              ...style,
            }
          : {
              position: 'absolute', top: 12, right: 16,
              padding: '2px 10px', border: '1px solid rgba(122,126,133,.4)', borderRadius: 4,
              opacity: 0.55, pointerEvents: 'none', transform: 'rotate(-3deg)',
              ...style,
            }
      }
    >
      <ProteanBrand size="stamp" style={fontSize ? { fontSize } : undefined} />
    </div>
  );
}
