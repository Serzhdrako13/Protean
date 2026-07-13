import { Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { PasswordPolicySettings } from '@/types/passwordPolicy';

// Shown above every "set/change password" field, admin and portal alike --
// without this, a user has no way to know the server will reject their
// choice until after they submit it (worse: on the portal, a rejected
// change can look identical to "wrong current password").
export function PasswordPolicyHint({ policy }: { policy: PasswordPolicySettings | null | undefined }) {
  const { t } = useTranslation('common');
  if (!policy) return null;
  const reqs = [t('passwordPolicy.minLength', { n: policy.min_length })];
  if (policy.require_upper) reqs.push(t('passwordPolicy.upper'));
  if (policy.require_lower) reqs.push(t('passwordPolicy.lower'));
  if (policy.require_digit) reqs.push(t('passwordPolicy.digit'));
  if (policy.require_symbol) reqs.push(t('passwordPolicy.symbol'));
  return (
    <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -8, marginBottom: 16 }}>
      {t('passwordPolicy.hint')}: {reqs.join(', ')}
    </Typography.Paragraph>
  );
}
