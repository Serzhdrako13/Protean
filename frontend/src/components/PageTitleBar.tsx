import { useEffect, useRef, useState, type ReactNode } from 'react';
import { ProteanStamp } from './ProteanBrand';

// Every admin-panel page's title row: the page's own <h2> on one side, a
// horizontal steel-colored Protean stamp on the other. The stamp's
// font-size is measured off the actual rendered <h2> (not hardcoded) via
// ResizeObserver, so it always matches -- including pages whose title size
// differs from the norm, or if a page's title size changes later (theme,
// zoom, a future redesign) -- without needing to hunt down every call site.
//
// `extra` (a page-level action button, e.g. "Add server") renders on its
// OWN row below the title+stamp row, right-aligned -- deliberately not
// crowded into the same row as the stamp (that read as cluttered/unclear
// which control was which). Still near the top of the page, not buried
// below a potentially long table: "add a new thing" buttons are the kind of
// control that needs to stay immediately discoverable.
//
// `prefix` is for pages whose title is preceded by something else on the
// left (e.g. a "back" button) -- it renders outside the measured <h2>, so
// it doesn't skew the stamp's size measurement.
export function PageTitleBar({
  children, extra, prefix,
}: { children: ReactNode; extra?: ReactNode; prefix?: ReactNode }) {
  const titleRef = useRef<HTMLHeadingElement>(null);
  const [stampSize, setStampSize] = useState<number>(20);

  useEffect(() => {
    const el = titleRef.current;
    if (!el) return;
    const measure = () => {
      const px = parseFloat(getComputedStyle(el).fontSize);
      if (!Number.isNaN(px)) setStampSize(px * 0.55);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {prefix}
          <h2 ref={titleRef} style={{ margin: 0 }}>{children}</h2>
        </div>
        <ProteanStamp horizontal fontSize={stampSize} />
      </div>
      {extra && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          {extra}
        </div>
      )}
    </div>
  );
}
