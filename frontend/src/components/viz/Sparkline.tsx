import { useEffect, useRef, type RefObject } from 'react';
import { useTranslation } from 'react-i18next';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import type { TrafficPoint } from '@/types/api';
import { useTheme } from '@/hooks/useTheme';

function hexToRgba(hex: string, alpha: number): string {
  const m = hex.replace('#', '');
  const r = parseInt(m.slice(0, 2), 16);
  const g = parseInt(m.slice(2, 4), 16);
  const b = parseInt(m.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

function areaSeries(color: string) {
  return (u: uPlot, seriesIdx: number) => {
    const ctx = u.ctx;
    // u.bbox.top/height can be non-finite for one paint if the container
    // hasn't been laid out yet when uPlot first draws (e.g. width still 0
    // right after mount) -- createLinearGradient throws on a non-finite
    // arg and crashes the whole SPA (uncaught in React's render path), so
    // fall back to 0 rather than letting that reach the canvas API.
    const top = Number.isFinite(u.bbox.top) ? u.bbox.top : 0;
    const height = Number.isFinite(u.bbox.height) ? u.bbox.height : 0;
    const grad = ctx.createLinearGradient(0, top, 0, top + height);
    grad.addColorStop(0, hexToRgba(color, 0.28));
    grad.addColorStop(1, hexToRgba(color, 0.02));
    return grad;
  };
}

const RX_COLOR = '#52c41a';
const TX_COLOR = '#1677ff';

// Shown over the chart area instead of an empty uPlot canvas when there
// isn't enough data yet to draw a line (a fresh/inactive server, or one
// with no traffic sampled in the selected range) -- an abstract dimmed
// wave rather than just blank space, so it reads as "no data yet", not as
// a broken chart.
function NoDataPlaceholder() {
  const { t } = useTranslation(['dashboard']);
  return (
    <div
      style={{
        position: 'absolute', inset: 0, borderRadius: 6, overflow: 'hidden',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--ant-color-fill-tertiary, rgba(128,128,128,.06))',
      }}
    >
      <svg width="100%" height="100%" viewBox="0 0 300 100" preserveAspectRatio="none" style={{ position: 'absolute', inset: 0, opacity: 0.35 }}>
        <path
          d="M0,65 C35,25 70,85 105,55 C140,20 175,75 210,45 C240,20 270,60 300,40"
          fill="none"
          stroke="var(--ant-color-text-tertiary, #999)"
          strokeWidth="2"
        />
      </svg>
      <span style={{ position: 'relative', fontSize: 12, color: 'var(--ant-color-text-tertiary)' }}>
        {t('dashboard:noTrafficData')}
      </span>
    </div>
  );
}

function human(bps: number): string {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let v = bps;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function Sparkline({
  points, legendContainerRef,
}: {
  points: TrafficPoint[];
  // When given, uPlot's own legend DOM node (Time/RX/TX, live-updating on
  // hover) is physically moved into this element instead of sitting below
  // the chart -- a real DOM re-parent, not a redrawn copy, so it keeps
  // uPlot's hover behavior for free instead of reimplementing it.
  legendContainerRef?: RefObject<HTMLDivElement | null>;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const plotRef = useRef<uPlot | null>(null);
  const { isDark } = useTheme();

  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;

    function create(width: number) {
      const data: uPlot.AlignedData = [
        points.map((p) => p.t),
        points.map((p) => p.rx),
        points.map((p) => p.tx),
      ];
      // Canvas 2D's strokeStyle/fillStyle can't resolve CSS var() at all --
      // an unresolvable value is just silently ignored (spec: invalid color
      // assignments keep whatever was previously set), which is why axis
      // labels using var(--ant-color-*) were nearly invisible in BOTH
      // themes rather than merely low-contrast in one. Literal hex per
      // theme instead, resolved in JS.
      const axisColor = isDark ? '#d9d9d9' : '#333333';
      const opts: uPlot.Options = {
        width,
        height: 160,
        padding: [12, 8, 8, 8],
        cursor: { drag: { x: false, y: false } },
        legend: { show: true },
        axes: [
          { stroke: axisColor, grid: { stroke: 'rgba(128,128,128,.15)' } },
          {
            stroke: axisColor,
            grid: { stroke: 'rgba(128,128,128,.15)' },
            values: (_u, vals) => vals.map((v) => human(v)),
          },
        ],
        series: [
          { label: 'Time' },
          { label: 'RX', stroke: RX_COLOR, width: 1.5, fill: areaSeries(RX_COLOR) },
          { label: 'TX', stroke: TX_COLOR, width: 1.5, fill: areaSeries(TX_COLOR) },
        ],
      };
      plotRef.current = new uPlot(opts, data, el);
      if (legendContainerRef?.current) {
        const legendEl = plotRef.current.root.querySelector('.u-legend');
        if (legendEl) legendContainerRef.current.appendChild(legendEl);
      }
    }

    // clientWidth can still be 0 on the very first paint (container not yet
    // laid out -- e.g. right after a route transition), and uPlot given a
    // 0 width computes a non-finite internal bbox that crashes the canvas
    // gradient call. Wait for a real, nonzero size via ResizeObserver
    // before ever constructing the plot, instead of reading clientWidth
    // once synchronously at mount.
    const ro = new ResizeObserver(() => {
      const width = el.clientWidth;
      if (width <= 0) return;
      if (!plotRef.current) {
        create(width);
      } else {
        plotRef.current.setSize({ width, height: 160 });
      }
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      plotRef.current?.destroy();
      plotRef.current = null;
      // The legend was re-parented out of the plot's own root, so
      // destroy()'s cleanup of that root doesn't remove it -- do it here,
      // or a theme flip (which recreates the plot) would pile up a second
      // legend table alongside the first.
      if (legendContainerRef?.current) legendContainerRef.current.innerHTML = '';
    };
    // Deliberately excludes `points`: the effect only (re)creates the plot
    // (on mount or a theme flip, since axis colors are baked into the uPlot
    // options at construction time); a separate effect below pushes new
    // data into the already-created instance instead of recreating it on
    // every poll tick.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isDark]);

  useEffect(() => {
    plotRef.current?.setData([
      points.map((p) => p.t),
      points.map((p) => p.rx),
      points.map((p) => p.tx),
    ]);
  }, [points]);

  return (
    <div style={{ position: 'relative' }}>
      <div ref={ref} style={{ width: '100%' }} />
      {points.length < 2 && <NoDataPlaceholder />}
    </div>
  );
}
