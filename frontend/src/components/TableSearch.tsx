import { Input } from 'antd';
import { SearchOutlined } from '@ant-design/icons';

export function TableSearch({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <Input
      allowClear
      prefix={<SearchOutlined />}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={{ width: 240, marginBottom: 16 }}
    />
  );
}
