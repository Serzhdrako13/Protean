import { useTranslation } from 'react-i18next';
import ruRU from 'antd/locale/ru_RU';
import enUS from 'antd/locale/en_US';
import { setLang, type Lang } from '@/i18n';

// Thin wrapper over react-i18next's language state, plus the matching AntD
// locale (date pickers/pagination/etc. own strings) -- one hook so every
// ConfigProvider in the app (admin SPA, login, portal) switches both at
// once instead of drifting independently.
export function useLang() {
  const { i18n } = useTranslation();
  const lang = (i18n.language as Lang) || 'en';
  const antdLocale = lang === 'en' ? enUS : ruRU;
  const toggleLang = () => setLang(lang === 'en' ? 'ru' : 'en');
  return { lang, antdLocale, setLang: (l: Lang) => setLang(l), toggleLang };
}
