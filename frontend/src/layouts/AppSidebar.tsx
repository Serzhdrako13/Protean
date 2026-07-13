import { useEffect, useRef, useState } from 'react';
import { Layout, Menu, Avatar, Dropdown } from 'antd';
import type { MenuProps } from 'antd';
import {
  DashboardOutlined,
  CloudServerOutlined,
  ClusterOutlined,
  PartitionOutlined,
  BellOutlined,
  FileTextOutlined,
  HistoryOutlined,
  TeamOutlined,
  InboxOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
  SafetyOutlined,
  KeyOutlined,
  ClearOutlined,
  SettingOutlined,
  UserOutlined,
  LogoutOutlined,
  QuestionCircleOutlined,
  BulbOutlined,
  MoonOutlined,
  DownOutlined,
  ExportOutlined,
  TranslationOutlined,
} from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '@/hooks/useTheme';
import { useLang } from '@/hooks/useLang';
import { useAccountQuery, useLogoutMutation, useSetLanguageMutation } from '@/api/queries/account';
import { ProteanBrand } from '@/components/ProteanBrand';

const STORAGE_COLLAPSED = 'protean-sidebar-collapsed';

export function AppSidebar() {
  const { t } = useTranslation();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(STORAGE_COLLAPSED) === 'true');
  const { isDark, toggleTheme } = useTheme();
  const { lang, toggleLang, setLang } = useLang();
  const location = useLocation();
  const navigate = useNavigate();
  const logout = useLogoutMutation();
  const { data: account } = useAccountQuery();
  const setLanguage = useSetLanguageMutation();

  // Apply the account's saved language preference once, on load -- lets a
  // choice made on one device/browser follow the user to another instead
  // of always falling back to browser/localStorage detection there.
  const appliedAccountLang = useRef(false);
  useEffect(() => {
    if (appliedAccountLang.current || !account?.language) return;
    appliedAccountLang.current = true;
    if (account.language !== lang) setLang(account.language as 'ru' | 'en');
  }, [account?.language, lang, setLang]);

  function onToggleLang() {
    const next = lang === 'en' ? 'ru' : 'en';
    toggleLang();
    setLanguage.mutate(next);
  }

  useEffect(() => {
    localStorage.setItem(STORAGE_COLLAPSED, String(collapsed));
  }, [collapsed]);

  // Grouped nav (backlog item 8): the flat 13-item list got hard to scan,
  // so frequent/core resources stay flat at top and everything else is
  // grouped by what it's actually for -- matches how similar network-admin
  // panels (e.g. OPNsense's System → Settings/Administration) split this
  // exact kind of long tail, and Miller's-law guidance that well-grouped
  // items beat an arbitrarily short flat list.
  const navItems = [
    { key: '/', icon: <DashboardOutlined />, label: t('nav.dashboard') },
    { key: '/servers', icon: <CloudServerOutlined />, label: t('nav.servers') },
    { key: '/nodes', icon: <ClusterOutlined />, label: t('nav.nodes') },
    { key: '/subnets', icon: <PartitionOutlined />, label: t('nav.subnets') },
    {
      key: 'group-users', icon: <TeamOutlined />, label: t('nav.groups.users'),
      children: [
        { key: '/users', icon: <TeamOutlined />, label: t('nav.users') },
        { key: '/access-requests', icon: <InboxOutlined />, label: t('nav.accessRequests') },
        { key: '/admin-portal', icon: <GlobalOutlined />, label: t('nav.adminPortal') },
      ],
    },
    {
      key: 'group-logs', icon: <FileTextOutlined />, label: t('nav.groups.logs'),
      children: [
        { key: '/audit', icon: <FileTextOutlined />, label: t('nav.audit') },
        { key: '/connection-history', icon: <HistoryOutlined />, label: t('nav.connectionHistory') },
      ],
    },
    {
      key: 'group-settings', icon: <SettingOutlined />, label: t('nav.groups.settings'),
      children: [
        { key: '/notifications', icon: <BellOutlined />, label: t('nav.notifications') },
        { key: '/tls', icon: <SafetyCertificateOutlined />, label: t('nav.tls') },
        { key: '/login-security', icon: <SafetyOutlined />, label: t('nav.loginSecurity') },
        { key: '/auth-methods', icon: <KeyOutlined />, label: t('nav.authMethods') },
        { key: '/data-retention', icon: <ClearOutlined />, label: t('nav.dataRetention') },
      ],
    },
  ];
  // Flattened (group children pulled up alongside top-level leaves) purely
  // for path-matching below -- navItems itself stays nested for rendering.
  const flatNavKeys = navItems.flatMap((it) => it.children?.map((c) => c.key) ?? [it.key]);

  // /providers/*, /servers/:id/providers and /install are sub-flows of
  // "Серверы" (reached from a server row's Провайдеры/Установить VPN
  // buttons) — without this, visiting any of them found no match below and
  // fell back to "/" (Панель), highlighting the wrong item. /account and
  // /help live outside the left nav entirely (reached from the avatar
  // dropdown) and correctly highlight nothing.
  const path = location.pathname;
  let selectedKey: string | undefined;
  if (path === '/') {
    selectedKey = '/';
  } else if (path.startsWith('/providers/') || path === '/install' || path.startsWith('/servers')) {
    selectedKey = '/servers';
  } else {
    selectedKey = flatNavKeys.find((key) => key !== '/' && path.startsWith(key));
  }
  // The group containing the active leaf auto-expands so the highlighted
  // item is actually visible, not just its collapsed parent -- but once
  // opened/closed by hand, that manual state should stick (not get
  // clobbered by every route change), so this only seeds useState's
  // initial value, not an effect that re-forces it on navigation.
  const activeGroup = navItems.find((it) => it.children?.some((c) => c.key === selectedKey))?.key;
  const [openKeys, setOpenKeys] = useState<string[]>(() => (activeGroup ? [activeGroup] : []));

  // Standard admin-panel pattern (AntD Pro's AvatarDropdown, GitHub, etc.):
  // account-related actions live behind one avatar+name control at the
  // bottom of the sider, not as several cramped inline mini-links.
  const userMenuItems: MenuProps['items'] = [
    { key: 'account', icon: <UserOutlined />, label: t('nav.account'), onClick: () => navigate('/account') },
    {
      key: 'theme',
      icon: isDark ? <BulbOutlined /> : <MoonOutlined />,
      label: isDark ? t('nav.lightTheme') : t('nav.darkTheme'),
      onClick: toggleTheme,
    },
    {
      key: 'lang',
      icon: <TranslationOutlined />,
      label: lang === 'ru' ? 'English' : 'Русский',
      onClick: onToggleLang,
    },
    { type: 'divider' },
    {
      key: 'portal',
      icon: <ExportOutlined />,
      label: t('nav.selfServicePortal'),
      // /portal is a separate standalone entry outside this SPA's router
      // (its own login, no sidebar) — a real navigation, not client-side
      // routing, and opened in a new tab so the admin doesn't lose their
      // own session/place in the panel.
      onClick: () => window.open('/portal', '_blank', 'noopener'),
    },
    { key: 'help', icon: <QuestionCircleOutlined />, label: t('nav.help'), onClick: () => navigate('/help') },
    { type: 'divider' },
    { key: 'logout', icon: <LogoutOutlined />, label: t('actions.logout'), danger: true, onClick: () => logout.mutate() },
  ];

  return (
    <Layout.Sider
      collapsible
      collapsed={collapsed}
      onCollapse={setCollapsed}
      breakpoint="md"
      width={260}
      style={{ position: 'sticky', top: 0, height: '100vh', overflow: 'auto', display: 'flex', flexDirection: 'column' }}
    >
      <div
        style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          padding: '14px 16px', whiteSpace: 'nowrap', overflow: 'hidden',
        }}
      >
        {collapsed
          ? <ProteanBrand size="lg" style={{ fontSize: 22, letterSpacing: 0 }}>P</ProteanBrand>
          : (
            <>
              <ProteanBrand size="lg" />
              <span style={{ fontSize: 19, letterSpacing: '0.06em', color: 'rgba(255,255,255,.55)', marginTop: 2 }}>
                {t('controlPanelTag')}
              </span>
            </>
          )}
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={selectedKey ? [selectedKey] : []}
        openKeys={openKeys}
        onOpenChange={setOpenKeys}
        onClick={({ key }) => navigate(key)}
        items={navItems}
        style={{ flex: 1 }}
      />
      <Dropdown menu={{ items: userMenuItems }} trigger={['click']} placement="topRight">
        <div
          style={{
            display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
            justifyContent: collapsed ? 'center' : 'flex-start',
            // 20px, not 16px: matches AntD Menu.Item's actual icon inset in
            // expanded mode (itemMarginInline 4px + itemPaddingInline 16px,
            // both antd default tokens) -- 16px alone sat 4px left of the
            // nav icons above it.
            padding: collapsed ? '12px 0' : '12px 20px',
            borderTop: '1px solid rgba(255,255,255,.12)',
          }}
        >
          <Avatar size="small" icon={<UserOutlined />} />
          {!collapsed && (
            <>
              <span style={{ flex: 1, color: 'rgba(255,255,255,.85)', fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {account?.username ?? '…'}
              </span>
              <DownOutlined style={{ fontSize: 10, color: 'rgba(255,255,255,.5)' }} />
            </>
          )}
        </div>
      </Dropdown>
    </Layout.Sider>
  );
}
