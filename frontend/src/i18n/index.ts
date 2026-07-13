import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Auto-loads every locales/<lang>/<namespace>.json at build time -- new
// namespace files (one per page, see the extraction convention in
// CONVENTIONS below) need no manual import list to keep in sync.
const modules = import.meta.glob<{ default: Record<string, unknown> }>('./locales/*/*.json', { eager: true });

const resources: Record<string, Record<string, Record<string, unknown>>> = {};
for (const path in modules) {
  // path shape: "./locales/<lang>/<namespace>.json"
  const match = /\.\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  if (!match) continue;
  const [, lang, ns] = match;
  resources[lang] ??= {};
  resources[lang][ns] = modules[path].default;
}

const STORAGE_LANG = 'protean-lang';
export type Lang = 'ru' | 'en';

function readLang(): Lang {
  const stored = localStorage.getItem(STORAGE_LANG);
  return stored === 'ru' ? 'ru' : 'en';
}

export const initialLang = readLang();

void i18n.use(initReactI18next).init({
  resources,
  lng: initialLang,
  fallbackLng: 'en',
  defaultNS: 'common',
  ns: Object.keys(resources.ru ?? {}),
  interpolation: { escapeValue: false }, // React already escapes
  returnNull: false,
});

export function setLang(lang: Lang): void {
  void i18n.changeLanguage(lang);
  localStorage.setItem(STORAGE_LANG, lang);
}

export function getLang(): Lang {
  return (i18n.language as Lang) || 'en';
}

export default i18n;
