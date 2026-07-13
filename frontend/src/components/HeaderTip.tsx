import { Tooltip } from 'antd';
import { QuestionCircleOutlined } from '@ant-design/icons';

// Table-column-header helper: label + a small (?) tooltip explaining
// anything not self-evident (jargon, non-obvious logic). Use as a column's
// `title` when the plain text alone wouldn't be enough.
export function HeaderTip({ label, tip }: { label: string; tip: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {label}
      <Tooltip title={tip}>
        <QuestionCircleOutlined style={{ color: 'var(--ant-color-text-tertiary)' }} />
      </Tooltip>
    </span>
  );
}
