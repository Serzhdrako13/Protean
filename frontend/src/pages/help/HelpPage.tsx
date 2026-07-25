import { useNavigate } from 'react-router-dom';
import { Card, Typography, Button, Space } from 'antd';
import { ArrowLeftOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { PageShell } from '@/layouts/PageShell';
import { PageTitleBar } from '@/components/PageTitleBar';
import { useVersionQuery } from '@/api/queries/version';

const { Title, Paragraph } = Typography;

export function HelpPage() {
  const navigate = useNavigate();
  const { t } = useTranslation(['help', 'common']);
  const { data: versionData } = useVersionQuery();
  return (
    <PageShell>
      <PageTitleBar
        prefix={<Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/')} title={t('help:backToHome')} />}
      >
        {t('common:nav.help')}
      </PageTitleBar>
      <Card>
        <Typography>
          <Title level={4}>{t('help:sections.howItWorks.title')}</Title>
          <Paragraph>
            {t('help:sections.howItWorks.body')}
          </Paragraph>
          <Title level={4}>{t('help:sections.quickStart.title')}</Title>
          <Paragraph>
            {t('help:sections.quickStart.step1')}<br />
            {t('help:sections.quickStart.step2')}<br />
            {t('help:sections.quickStart.step3')}<br />
            {t('help:sections.quickStart.step4')}
          </Paragraph>
          <Title level={4}>{t('help:sections.providerTabs.title')}</Title>
          <Paragraph>
            <b>{t('help:sections.providerTabs.overviewLabel')}</b> {t('help:sections.providerTabs.overviewText')}<br />
            <b>{t('help:sections.providerTabs.settingsLabel')}</b> {t('help:sections.providerTabs.settingsText')}
          </Paragraph>
          <Title level={4}>{t('help:sections.multipleInstances.title')}</Title>
          <Paragraph>
            {t('help:sections.multipleInstances.body')}
          </Paragraph>
          <Title level={4}>{t('help:sections.xray.title')}</Title>
          <Paragraph>
            {t('help:sections.xray.body')}
          </Paragraph>
          <Title level={4}>{t('help:sections.menuSections.title')}</Title>
          <Paragraph>
            <b>{t('common:nav.servers')}</b> {t('help:sections.menuSections.serversText')}<br />
            <b>{t('help:sections.menuSections.meshLabel')}</b> {t('help:sections.menuSections.meshText')}<br />
            <b>{t('common:nav.subnets')}</b> {t('help:sections.menuSections.subnetsText')}<br />
            <b>{t('common:nav.notifications')}</b> {t('help:sections.menuSections.notificationsText')}<br />
            <b>{t('common:nav.audit')}</b> {t('help:sections.menuSections.auditText')}<br />
            <b>{t('common:nav.account')}</b> {t('help:sections.menuSections.accountText')}
          </Paragraph>
          <Title level={4}>{t('help:sections.dockerSameHost.title')}</Title>
          <Paragraph>
            {t('help:sections.dockerSameHost.body')}
          </Paragraph>
          <Title level={4}>{t('help:sections.license.title')}</Title>
          <Paragraph>
            {t('help:sections.license.body')}<br />
            <a href="/license.txt" target="_blank" rel="noreferrer">{t('help:sections.license.viewFull')}</a>
          </Paragraph>
          {versionData && (
            <Paragraph type="secondary" style={{ fontSize: 12 }}>
              {t('help:version', { version: versionData.version })}
            </Paragraph>
          )}
        </Typography>
      </Card>
    </PageShell>
  );
}
