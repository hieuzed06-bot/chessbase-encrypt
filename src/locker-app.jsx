'use client';

import { useState } from 'react';
import {
  Badge,
  Body1,
  Body2,
  Button,
  Card,
  CardHeader,
  Caption1,
  Divider,
  Subtitle2,
  Tab,
  TabList,
  Title1,
  Title3,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import {
  Code24Regular,
  LockClosed24Regular,
  LockOpen24Regular,
  Send24Regular,
  ShieldCheckmark24Regular,
  WeatherMoon24Regular,
  WeatherSunny24Regular,
} from '@fluentui/react-icons';
import { buildProtectedPage, downloadBytes, MAX_CIPHER_BYTES, packFilePayload, parseFilePayload } from '../app.js';
import { MAX_PGN_BYTES, MAX_SOURCE_BYTES, fromPGN, toPGN } from '../codec.js';
import { decryptRawBytes, encryptRawBytes, validateEncryptionPassword } from '../crypto-v3.js';
import { ProtectPanel } from './protect-panel.jsx';
import { UnlockPanel } from './unlock-panel.jsx';

const useStyles = makeStyles({
  page: {
    minHeight: '100vh',
    backgroundColor: tokens.colorNeutralBackground2,
    color: tokens.colorNeutralForeground1,
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalM,
    paddingLeft: tokens.spacingHorizontalXXL,
    paddingRight: tokens.spacingHorizontalXXL,
    paddingTop: tokens.spacingVerticalM,
    paddingBottom: tokens.spacingVerticalM,
    backgroundColor: tokens.colorNeutralBackground1,
    borderBottom: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalM,
  },
  brandMark: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: tokens.spacingVerticalS,
    paddingRight: tokens.spacingHorizontalS,
    paddingBottom: tokens.spacingVerticalS,
    paddingLeft: tokens.spacingHorizontalS,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground2,
  },
  brandText: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXXS,
  },
  headerActions: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalS,
  },
  main: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXXL,
    maxWidth: '1160px',
    marginLeft: 'auto',
    marginRight: 'auto',
    paddingTop: tokens.spacingVerticalXXL,
    paddingRight: tokens.spacingHorizontalXXL,
    paddingBottom: tokens.spacingVerticalXXXL,
    paddingLeft: tokens.spacingHorizontalXXL,
    '@media (max-width: 480px)': {
      paddingRight: tokens.spacingHorizontalL,
      paddingLeft: tokens.spacingHorizontalL,
    },
  },
  hero: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    alignItems: 'center',
    gap: tokens.spacingHorizontalXXXL,
  },
  heroCopy: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    gap: tokens.spacingVerticalM,
    maxWidth: '680px',
  },
  heroTitle: {
    maxWidth: '680px',
    textWrap: 'balance',
  },
  heroDescription: {
    maxWidth: '640px',
    color: tokens.colorNeutralForeground2,
  },
  securityCard: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
    paddingTop: tokens.spacingVerticalL,
    paddingRight: tokens.spacingHorizontalL,
    paddingBottom: tokens.spacingVerticalL,
    paddingLeft: tokens.spacingHorizontalL,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusXLarge,
    backgroundColor: tokens.colorNeutralBackground1,
    boxShadow: tokens.shadow4,
  },
  securityHeading: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalM,
  },
  securityIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: tokens.spacingVerticalS,
    paddingRight: tokens.spacingHorizontalS,
    paddingBottom: tokens.spacingVerticalS,
    paddingLeft: tokens.spacingHorizontalS,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground2,
  },
  securityText: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXXS,
  },
  facts: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: tokens.spacingHorizontalM,
  },
  fact: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXS,
  },
  secondary: {
    color: tokens.colorNeutralForeground2,
  },
  toolSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
  tabs: {
    alignSelf: 'flex-start',
    maxWidth: '100%',
  },
  toolCard: {
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusXLarge,
    backgroundColor: tokens.colorNeutralBackground1,
    boxShadow: tokens.shadow8,
  },
  toolContent: {
    paddingTop: tokens.spacingVerticalL,
    paddingRight: tokens.spacingHorizontalL,
    paddingBottom: tokens.spacingVerticalL,
    paddingLeft: tokens.spacingHorizontalL,
  },
  stepsSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
  },
  stepsHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalM,
  },
  stepsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: tokens.spacingHorizontalM,
  },
  stepCard: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    gap: tokens.spacingVerticalS,
    paddingTop: tokens.spacingVerticalL,
    paddingRight: tokens.spacingHorizontalL,
    paddingBottom: tokens.spacingVerticalL,
    paddingLeft: tokens.spacingHorizontalL,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusXLarge,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  stepTop: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
  },
  stepIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: tokens.spacingVerticalXS,
    paddingRight: tokens.spacingHorizontalXS,
    paddingBottom: tokens.spacingVerticalXS,
    paddingLeft: tokens.spacingHorizontalXS,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground2,
  },
  stepNumber: {
    color: tokens.colorNeutralForeground3,
  },
  footer: {
    display: 'flex',
    flexWrap: 'wrap',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: tokens.spacingHorizontalM,
    paddingTop: tokens.spacingVerticalL,
    borderTop: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
  },
});

function StepCard({ number, icon: Icon, title, description }) {
  const styles = useStyles();

  return (
    <Card className={styles.stepCard}>
      <div className={styles.stepTop}>
        <span className={styles.stepIcon} aria-hidden="true"><Icon /></span>
        <Caption1 className={styles.stepNumber}>{number}</Caption1>
      </div>
      <Subtitle2 as="h3">{title}</Subtitle2>
      <Body2 className={styles.secondary}>{description}</Body2>
    </Card>
  );
}

function feedback(intent, title, message) {
  return { intent, title, message };
}

export function LockerApp({ mode, onToggleTheme }) {
  const styles = useStyles();
  const [activeTab, setActiveTab] = useState('protect');
  const [source, setSource] = useState('');
  const [sourceFile, setSourceFile] = useState(null);
  const [encryptPassword, setEncryptPassword] = useState('');
  const [encryptConfirmation, setEncryptConfirmation] = useState('');
  const [encryptedResult, setEncryptedResult] = useState(null);
  const [protectFeedback, setProtectFeedback] = useState(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [cipherText, setCipherText] = useState('');
  const [cipherFile, setCipherFile] = useState(null);
  const [cipherFileName, setCipherFileName] = useState('');
  const [decryptPassword, setDecryptPassword] = useState('');
  const [decryptedResult, setDecryptedResult] = useState(null);
  const [decryptFeedback, setDecryptFeedback] = useState(null);
  const [isDecrypting, setIsDecrypting] = useState(false);

  function clearEncryptionFeedback() {
    setEncryptedResult(null);
    setProtectFeedback(null);
  }

  function handleSourceChange(value) {
    setSource(value);
    setSourceFile(null);
    clearEncryptionFeedback();
  }

  function handleSourceFileChange(file) {
    setSourceFile(file);
    setSource('');
    clearEncryptionFeedback();
  }

  async function handleEncrypt() {
    setProtectFeedback(null);
    setEncryptedResult(null);

    if (encryptPassword !== encryptConfirmation) {
      setProtectFeedback(feedback('error', 'Passwords do not match', 'Re-enter the same passphrase in both password fields.'));
      return;
    }

    const passwordError = validateEncryptionPassword(encryptPassword);
    if (passwordError) {
      setProtectFeedback(feedback('error', 'Check your passphrase', passwordError));
      return;
    }

    if (!sourceFile && !source.trim()) {
      setProtectFeedback(feedback('error', 'Add something to protect', 'Choose a supported file or paste source text first.'));
      return;
    }

    if (sourceFile && sourceFile.size > MAX_SOURCE_BYTES) {
      setProtectFeedback(feedback('error', 'File is too large', 'The encrypted payload limit is 1 MiB.'));
      return;
    }

    setIsEncrypting(true);

    try {
      const sourceBytes = sourceFile
        ? new Uint8Array(await sourceFile.arrayBuffer())
        : new TextEncoder().encode(source);
      const payload = sourceFile ? packFilePayload(sourceFile, sourceBytes) : sourceBytes;

      if (payload.length > MAX_SOURCE_BYTES) {
        throw new Error('File or source exceeds the 1 MiB encrypted payload limit.');
      }

      const bytes = await encryptRawBytes(payload, encryptPassword);
      const pgn = toPGN(bytes);
      setEncryptedResult({ bytes, pgn });
      setProtectFeedback(feedback(
        'success',
        'Encryption complete',
        'Your encrypted data is ready to copy or download as a CCX file or protected HTML page.',
      ));
    } catch (error) {
      setProtectFeedback(feedback(
        'error',
        'Could not encrypt this content',
        error instanceof Error ? error.message : 'An unexpected encryption error occurred.',
      ));
    } finally {
      setIsEncrypting(false);
    }
  }

  async function handleCopyPgn() {
    try {
      await navigator.clipboard.writeText(encryptedResult.pgn);
      setProtectFeedback(feedback('success', 'PGN copied', 'The encrypted chess notation is on your clipboard.'));
    } catch {
      setProtectFeedback(feedback('error', 'Clipboard unavailable', 'Your browser did not allow clipboard access.'));
    }
  }

  function handleDownloadCcx() {
    downloadBytes(encryptedResult.bytes, 'protected-file.ccx');
    setProtectFeedback(feedback('success', 'Download started', 'Your encrypted .ccx file is being saved.'));
  }

  function handleDownloadPage() {
    const page = buildProtectedPage(encryptedResult.pgn);
    downloadBytes(new TextEncoder().encode(page), 'protected-code.html', 'text/html');
    setProtectFeedback(feedback('success', 'Download started', 'Your self-decrypting protected HTML page is being saved.'));
  }

  function handleClearEncryption() {
    setSource('');
    setSourceFile(null);
    setEncryptPassword('');
    setEncryptConfirmation('');
    setEncryptedResult(null);
    setProtectFeedback(null);
  }

  function handleCipherTextChange(value) {
    setCipherText(value);
    setCipherFile(null);
    setCipherFileName('');
    setDecryptedResult(null);
    setDecryptFeedback(null);
  }

  async function handleCipherFileSelect(file) {
    setCipherText('');
    setCipherFile(null);
    setCipherFileName('');
    setDecryptedResult(null);
    setDecryptFeedback(null);

    const extension = (file.name.split('.').pop() || '').toLowerCase();
    if (extension === 'ccx') {
      if (file.size > MAX_CIPHER_BYTES) {
        setDecryptFeedback(feedback('error', 'Encrypted file is too large', 'This CCX file exceeds the supported size limit.'));
        return;
      }
      setCipherFile(file);
      setCipherFileName(`${file.name} · ${formatBytes(file.size)}`);
      setDecryptFeedback(feedback('info', 'CCX file ready', 'Enter the password to decrypt this file.'));
      return;
    }

    if (file.size > MAX_PGN_BYTES) {
      setDecryptFeedback(feedback('error', 'File is too large', 'PGN and protected HTML files must be 8 MiB or smaller.'));
      return;
    }

    try {
      setCipherText(await file.text());
      setCipherFileName(`${file.name} · ${formatBytes(file.size)}`);
      setDecryptFeedback(feedback('info', 'File loaded', 'Enter the password to decrypt this content.'));
    } catch {
      setDecryptFeedback(feedback('error', 'Could not read this file', 'Choose a valid CCX, PGN, text, or protected HTML file.'));
    }
  }

  async function handleDecrypt() {
    setDecryptFeedback(null);
    setDecryptedResult(null);

    if (!decryptPassword) {
      setDecryptFeedback(feedback('error', 'Password required', 'Enter the password used to protect this content.'));
      return;
    }

    let pgn = cipherText.trim();
    if (!pgn && !cipherFile) {
      setDecryptFeedback(feedback('error', 'Add encrypted content', 'Choose a .ccx file or paste PGN or protected HTML first.'));
      return;
    }

    if (pgn && new TextEncoder().encode(pgn).length > MAX_PGN_BYTES) {
      setDecryptFeedback(feedback('error', 'PGN is too large', 'PGN and protected HTML are limited to 8 MiB.'));
      return;
    }

    if (pgn.startsWith('<!DOCTYPE') || pgn.startsWith('<html')) {
      const match = (() => {
        const marker = 'const PGN=';
        const markerIndex = pgn.indexOf(marker);
        const contentStart = markerIndex < 0 ? -1 : pgn.indexOf('`', markerIndex + marker.length);
        const contentEnd = contentStart < 0 ? -1 : pgn.indexOf('`;', contentStart + 1);
        return contentStart < 0 || contentEnd < 0 ? null : [null, pgn.slice(contentStart + 1, contentEnd)];
      })();
      if (!match) {
        setDecryptFeedback(feedback('error', 'Protected HTML not recognized', 'Could not extract encrypted PGN from this HTML file.'));
        return;
      }
      pgn = match[1];
    }

    setIsDecrypting(true);

    try {
      const encryptedBytes = cipherFile
        ? new Uint8Array(await cipherFile.arrayBuffer())
        : fromPGN(pgn);
      const plaintext = await decryptRawBytes(encryptedBytes, decryptPassword);
      const file = parseFilePayload(plaintext);

      if (file) {
        downloadBytes(file.bytes, file.name, file.type);
        setDecryptedResult({ kind: 'file', fileName: file.name });
        setDecryptFeedback(feedback('success', 'File decrypted', `Download started: ${file.name}`));
      } else {
        const code = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
        const lineCount = code.split('\n').length;
        setDecryptedResult({
          kind: 'text',
          code,
          meta: `${lineCount} ${lineCount === 1 ? 'line' : 'lines'} · ${code.length.toLocaleString()} characters`,
        });
        setDecryptFeedback(feedback('success', 'Decryption complete', 'Authentication verified. Your plaintext is ready below.'));
      }
    } catch (error) {
      setDecryptFeedback(feedback(
        'error',
        'Could not decrypt this content',
        error instanceof Error ? error.message : 'The password may be wrong or the encrypted data may be damaged.',
      ));
    } finally {
      setIsDecrypting(false);
    }
  }

  async function handleCopyDecrypted() {
    if (decryptedResult?.kind !== 'text') return;

    try {
      await navigator.clipboard.writeText(decryptedResult.code);
      setDecryptFeedback(feedback('success', 'Code copied', 'The decrypted text is on your clipboard.'));
    } catch {
      setDecryptFeedback(feedback('error', 'Clipboard unavailable', 'Your browser did not allow clipboard access.'));
    }
  }

  function handleDecryptPasswordChange(value) {
    setDecryptPassword(value);
    setDecryptedResult(null);
    setDecryptFeedback(null);
  }

  function handleClearDecryption() {
    setCipherText('');
    setCipherFile(null);
    setCipherFileName('');
    setDecryptPassword('');
    setDecryptedResult(null);
    setDecryptFeedback(null);
  }

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <span className={styles.brandMark} aria-hidden="true"><LockClosed24Regular /></span>
          <div className={styles.brandText}>
            <Subtitle2>Code Locker</Subtitle2>
            <Caption1 className={styles.secondary}>Chess cipher workspace</Caption1>
          </div>
        </div>
        <div className={styles.headerActions}>
          <Badge appearance="tint" color="success">Local only</Badge>
          <Button
            appearance="subtle"
            icon={mode === 'light' ? <WeatherMoon24Regular /> : <WeatherSunny24Regular />}
            aria-label={`Switch to ${mode === 'light' ? 'dark' : 'light'} theme`}
            onClick={onToggleTheme}
          />
        </div>
      </header>

      <main className={styles.main}>
        <section className={styles.hero} aria-labelledby="page-title">
          <div className={styles.heroCopy}>
            <Badge appearance="tint" color="brand">PRIVATE BY DESIGN</Badge>
            <Title1 as="h1" id="page-title" className={styles.heroTitle}>
              Keep code private. Share it as chess notation.
            </Title1>
            <Body1 className={styles.heroDescription}>
              Protect source code and documents with AES-256-GCM, then encode the encrypted data as a chess game. Your files and passphrase never leave this browser.
            </Body1>
          </div>

          <Card className={styles.securityCard}>
            <div className={styles.securityHeading}>
              <span className={styles.securityIcon} aria-hidden="true"><ShieldCheckmark24Regular /></span>
              <div className={styles.securityText}>
                <Subtitle2 as="h2">Privacy built in</Subtitle2>
                <Caption1 className={styles.secondary}>Browser-only encryption</Caption1>
              </div>
            </div>
            <Divider />
            <div className={styles.facts}>
              <div className={styles.fact}>
                <Body2>Authenticated encryption</Body2>
                <Caption1 className={styles.secondary}>AES-256-GCM</Caption1>
              </div>
              <div className={styles.fact}>
                <Body2>Strong passphrase work factor</Body2>
                <Caption1 className={styles.secondary}>PBKDF2 · 1,000,000 iterations</Caption1>
              </div>
            </div>
          </Card>
        </section>

        <section className={styles.toolSection} aria-label="Encryption workspace">
          <TabList
            className={styles.tabs}
            selectedValue={activeTab}
            onTabSelect={(_, data) => setActiveTab(data.value)}
          >
            <Tab value="protect" icon={<LockClosed24Regular />}>Protect</Tab>
            <Tab value="unlock" icon={<LockOpen24Regular />}>Unlock</Tab>
          </TabList>

          <Card className={styles.toolCard}>
            <CardHeader
              header={<Subtitle2>{activeTab === 'protect' ? 'Create a protected file' : 'Open protected content'}</Subtitle2>}
              description={
                <Caption1>
                  {activeTab === 'protect'
                    ? 'Encrypt locally, then copy or download the chess cipher.'
                    : 'Use a CCX file, PGN, or self-decrypting HTML page.'}
                </Caption1>
              }
            />
            <div className={styles.toolContent}>
              {activeTab === 'protect' ? (
                <ProtectPanel
                  source={source}
                  onSourceChange={handleSourceChange}
                  sourceFile={sourceFile}
                  onSourceFileChange={handleSourceFileChange}
                  password={encryptPassword}
                  onPasswordChange={(value) => {
                    setEncryptPassword(value);
                    clearEncryptionFeedback();
                  }}
                  confirmation={encryptConfirmation}
                  onConfirmationChange={(value) => {
                    setEncryptConfirmation(value);
                    clearEncryptionFeedback();
                  }}
                  onEncrypt={handleEncrypt}
                  isEncrypting={isEncrypting}
                  feedback={protectFeedback}
                  result={encryptedResult}
                  onCopyPgn={handleCopyPgn}
                  onDownloadCcx={handleDownloadCcx}
                  onDownloadPage={handleDownloadPage}
                  onClear={handleClearEncryption}
                />
              ) : (
                <UnlockPanel
                  source={cipherText}
                  fileName={cipherFileName}
                  onSourceChange={handleCipherTextChange}
                  onFileSelect={handleCipherFileSelect}
                  password={decryptPassword}
                  onPasswordChange={handleDecryptPasswordChange}
                  onDecrypt={handleDecrypt}
                  isDecrypting={isDecrypting}
                  feedback={decryptFeedback}
                  result={decryptedResult}
                  onCopy={handleCopyDecrypted}
                  onClear={handleClearDecryption}
                />
              )}
            </div>
          </Card>
        </section>

        <section className={styles.stepsSection} aria-labelledby="steps-heading">
          <div className={styles.stepsHeader}>
            <div>
              <Title3 as="h2" id="steps-heading">A simple, private workflow</Title3>
              <Body2 className={styles.secondary}>The chess notation is an encoding layer; the encryption does the protecting.</Body2>
            </div>
            <Badge appearance="tint" color="brand">CCX v3</Badge>
          </div>
          <div className={styles.stepsGrid}>
            <StepCard
              number="01"
              icon={Code24Regular}
              title="Add your source"
              description="Paste code or choose a supported document. Nothing is uploaded."
            />
            <StepCard
              number="02"
              icon={ShieldCheckmark24Regular}
              title="Encrypt in your browser"
              description="A fresh salt and nonce protect every encryption with AES-GCM."
            />
            <StepCard
              number="03"
              icon={Send24Regular}
              title="Share the cipher"
              description="Copy the PGN, download a CCX file, or send a protected HTML page."
            />
          </div>
        </section>

        <footer className={styles.footer}>
          <Caption1 className={styles.secondary}>Code Locker · No uploads · No password recovery</Caption1>
          <Caption1 className={styles.secondary}>Share your passphrase through a separate channel.</Caption1>
        </footer>
      </main>
    </div>
  );
}
