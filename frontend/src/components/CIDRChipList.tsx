import { useState } from 'react';
import { Input, Button, Space, Tag } from 'antd';
import { PlusOutlined } from '@ant-design/icons';

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

interface CIDRChipListProps {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
}

// Keenetic-style "type an address/subnet, click Add, get a removable
// chip" list -- not Select mode="tags" (no clean hook for an explicit
// per-attempt Add step with inline validation) or NetworkGroupSelect's
// pattern (that's single-FK selection, this is a free-text multi-value
// list). Coarse client-side shape check only; the server re-validates
// and is authoritative.
export function CIDRChipList({ value, onChange, placeholder, disabled }: CIDRChipListProps) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState(false);

  function commit() {
    const v = draft.trim();
    if (!v) return;
    if (!CIDR_RE.test(v) || value.includes(v)) {
      setError(true);
      return;
    }
    onChange([...value, v]);
    setDraft('');
    setError(false);
  }

  function remove(v: string) {
    onChange(value.filter((d) => d !== v));
  }

  return (
    <div>
      <Space.Compact style={{ width: '100%' }}>
        <Input
          value={draft}
          disabled={disabled}
          placeholder={placeholder}
          status={error ? 'error' : undefined}
          onChange={(e) => {
            setDraft(e.target.value);
            setError(false);
          }}
          onPressEnter={commit}
        />
        <Button icon={<PlusOutlined />} disabled={disabled} onClick={commit} />
      </Space.Compact>
      {value.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <Space size={[4, 4]} wrap>
            {value.map((v) => (
              <Tag key={v} closable={!disabled} onClose={() => remove(v)}>
                {v}
              </Tag>
            ))}
          </Space>
        </div>
      )}
    </div>
  );
}
