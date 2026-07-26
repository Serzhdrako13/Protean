import { useEffect, useState } from 'react';
import { Select, Input, Space } from 'antd';
import { useNetworkGroupsQuery } from '@/api/queries/networkGroups';

interface NetworkGroupSelectProps {
  value: number | null | undefined;
  onChange: (next: { group_id: number | null; new_group_name?: string }) => void;
  noGroupLabel: string;
  newGroupLabel: string;
  newGroupPlaceholder: string;
  size?: 'small' | 'middle';
  style?: React.CSSProperties;
}

// Single-FK group picker shared by ProviderSettingsPanel and SubnetsPage:
// pick an existing group, "no group", or type a new name inline. Not
// mode="tags" -- that's for multiple free values, wrong shape for a
// single FK. Labels are passed in rather than owned here so each caller
// keeps its own i18n namespace instead of this component needing one.
export function NetworkGroupSelect({
  value, onChange, noGroupLabel, newGroupLabel, newGroupPlaceholder, size, style,
}: NetworkGroupSelectProps) {
  const { data: groups } = useNetworkGroupsQuery();
  const [selected, setSelected] = useState<number | 'none' | 'new'>(value ?? 'none');
  const [newName, setNewName] = useState('');

  useEffect(() => {
    if (selected !== 'new') setSelected(value ?? 'none');
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps

  function handleSelect(v: number | 'none' | 'new') {
    setSelected(v);
    if (v === 'new') return; // wait for the name input
    onChange({ group_id: v === 'none' ? null : v });
  }

  function commitNewName() {
    const name = newName.trim();
    if (name) onChange({ group_id: null, new_group_name: name });
  }

  return (
    <Space>
      <Select<number | 'none' | 'new'>
        size={size}
        style={{ width: 160, ...style }}
        value={selected}
        onChange={handleSelect}
        options={[
          { value: 'none', label: noGroupLabel },
          ...(groups ?? []).map((g) => ({ value: g.id, label: g.name })),
          { value: 'new', label: newGroupLabel },
        ]}
      />
      {selected === 'new' && (
        <Input
          size={size}
          autoFocus
          placeholder={newGroupPlaceholder}
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onPressEnter={commitNewName}
          onBlur={commitNewName}
          style={{ width: 160 }}
        />
      )}
    </Space>
  );
}
