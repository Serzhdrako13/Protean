import type { PasswordPolicySettings } from '@/types/passwordPolicy';

// Shared with the portal entry -- no react-query/antd-form-instance
// dependency here, just plain validation, so it's safe from both bundles.
// Mirrors internal/auth/password_policy.go's ValidatePassword exactly (same
// class definitions), so a password that passes here won't be rejected by
// the server with a surprise "must include a digit" after the fact.
export function passwordPolicyIssues(policy: PasswordPolicySettings, password: string): string[] {
  const issues: string[] = [];
  if (password.length < policy.min_length) issues.push('minLength');
  const hasUpper = /\p{Lu}/u.test(password);
  const hasLower = /\p{Ll}/u.test(password);
  const hasDigit = /\p{Nd}/u.test(password);
  const hasSymbol = /[\p{P}\p{S}]/u.test(password);
  if (policy.require_upper && !hasUpper) issues.push('upper');
  if (policy.require_lower && !hasLower) issues.push('lower');
  if (policy.require_digit && !hasDigit) issues.push('digit');
  if (policy.require_symbol && !hasSymbol) issues.push('symbol');
  return issues;
}
