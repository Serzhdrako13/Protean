import { useEffect, useState } from 'react';
import { Select, Input, Space, Button, Tooltip, message } from 'antd';
import { EditOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons';
import { useNetworkGroupsQuery, useNetworkGroupRenameMutation } from '@/api/queries/networkGroups';
import { ApiError } from '@/api/http-init';

interface NetworkGroupSelectProps {
  value: number | null | undefined;
  onChange: (next: { group_id: number | null; new_group_name?: string }) => void;
  noGroupLabel: string;
  newGroupLabel: string;
  newGroupPlaceholder: string;
  renameTooltip: string;
  size?: 'small' | 'middle';
  style?: React.CSSProperties;
}

// Single-FK group picker shared by ProviderSettingsPanel and SubnetsPage:
// pick an existing group, "no group", or type a new name inline. Not
// mode="tags" -- that's for multiple free values, wrong shape for a
// single FK. Labels are passed in rather than owned here so each caller
// keeps its own i18n namespace instead of this component needing one.
//
// Auto-generated names ("Сеть 1") are never a dead end -- the edit icon
// (shown whenever a real group is selected) renames it in place via
// PUT /api/network-groups/{id}, visible everywhere else immediately
// (shared ['network-groups'] query key).
export function NetworkGroupSelect({
  value, onChange, noGroupLabel, newGroupLabel, newGroupPlaceholder, renameTooltip, size, style,
}: NetworkGroupSelectProps) {
  const { data: groups } = useNetworkGroupsQuery();
  const rename = useNetworkGroupRenameMutation();
  const [selected, setSelected] = useState<number | 'none' | 'new'>(value ?? 'none');
  const [newName, setNewName] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [renameValue, setRenameValue] = useState('');

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

  function startRename() {
    if (typeof selected !== 'number') return;
    setRenameValue(groups?.find((g) => g.id === selected)?.name ?? '');
    setRenaming(true);
  }

  async function commitRename() {
    if (typeof selected !== 'number') return;
    const name = renameValue.trim();
    if (!name) { setRenaming(false); return; }
    try {
      await rename.mutateAsync({ id: selected, name });
      setRenaming(false);
    } catch (e) {
      if (e instanceof ApiError) message.error(e.message);
    }
  }

  if (renaming) {
    return (
      <Space>
        <Input
          size={size}
          autoFocus
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          onPressEnter={commitRename}
          style={{ width: 160 }}
        />
        <Button size={size} icon={<CheckOutlined />} onClick={commitRename} loading={rename.isPending} />
        <Button size={size} icon={<CloseOutlined />} onClick={() => setRenaming(false)} />
      </Space>
    );
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
      {typeof selected === 'number' && (
        <Tooltip title={renameTooltip}>
          <Button size={size} icon={<EditOutlined />} onClick={startRename} />
        </Tooltip>
      )}
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
