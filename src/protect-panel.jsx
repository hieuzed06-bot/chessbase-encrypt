'use client';

import { useRef } from 'react';
import {
  Body2,
  Button,
  Card,
  CardFooter,
  CardHeader,
  Caption1,
  Field,
  Input,
  Subtitle2,
  Textarea,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import {
  ArrowDownload24Regular,
  Attach24Regular,
  Copy24Regular,
  Delete24Regular,
  LockClosed24Regular,
} from '@fluentui/react-icons';
import { formatBytes } from '../app.js';
import { FeedbackMessage } from './ui-common.jsx';

const useStyles = makeStyles({
  panel: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalM,
  },
  panelIntro: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXS,
  },
  formGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    alignItems: 'start',
    gap: tokens.spacingHorizontalXXL,
    '@media (max-width: 480px)': {
      gridTemplateColumns: 'minmax(0, 1fr)',
    },
  },
  fieldStack: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
    minWidth: 0,
  },
  filePicker: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalM,
    paddingTop: tokens.spacingVerticalM,
    paddingRight: tokens.spacingHorizontalM,
    paddingBottom: tokens.spacingVerticalM,
    paddingLeft: tokens.spacingHorizontalM,
    border: `${tokens.strokeWidthThin} dashed ${tokens.colorNeutralStroke1}`,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  fileDescription: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXS,
    minWidth: 0,
    overflowWrap: 'anywhere',
  },
  hiddenInput: {
    display: 'none',
  },
  codeArea: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
  },
  feedback: {
    marginTop: tokens.spacingVerticalS,
  },
  resultCard: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
    paddingTop: tokens.spacingVerticalL,
    paddingRight: tokens.spacingHorizontalL,
    paddingBottom: tokens.spacingVerticalL,
    paddingLeft: tokens.spacingHorizontalL,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusXLarge,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  resultActions: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalS,
  },
  footer: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalS,
    paddingTop: tokens.spacingVerticalM,
  },
  muted: {
    color: tokens.colorNeutralForeground2,
    overflowWrap: 'anywhere',
  },
});

export function ProtectPanel({
  source,
  onSourceChange,
  sourceFile,
  onSourceFileChange,
  password,
  onPasswordChange,
  confirmation,
  onConfirmationChange,
  onEncrypt,
  isEncrypting,
  feedback,
  result,
  onCopyPgn,
  onDownloadCcx,
  onDownloadPage,
  onClear,
}) {
  const styles = useStyles();
  const fileInputRef = useRef(null);
  const sourceSummary = source
    ? `${source.split('\n').length} lines · ${formatBytes(new TextEncoder().encode(source).length)}`
    : 'Your text stays in this browser.';

  function handleFileChange(event) {
    const file = event.currentTarget.files?.[0] ?? null;
    event.currentTarget.value = '';
    if (file) onSourceFileChange(file);
  }

  function handleClear() {
    if (fileInputRef.current) fileInputRef.current.value = '';
    onClear();
  }

  return (
    <section className={styles.panel} aria-labelledby="protect-heading">
      <div className={styles.panelHeader}>
        <div className={styles.panelIntro}>
          <Subtitle2 as="h2" id="protect-heading">Protect code or documents</Subtitle2>
          <Body2 className={styles.muted}>Everything is encrypted locally in this browser.</Body2>
        </div>
        <Caption1>1 MiB maximum encrypted payload</Caption1>
      </div>

      <div className={styles.formGrid}>
        <div className={styles.fieldStack}>
          <Field label="Source code or terminal commands" hint={sourceSummary}>
            <Textarea
              value={source}
              onChange={(_, data) => onSourceChange(data.value)}
              placeholder={'Paste source code or terminal commands here…\n\nLua, Luau, JavaScript, Python, shell scripts, SQL, and more.'}
              rows={10}
              resize="vertical"
              className={styles.codeArea}
            />
          </Field>

          <div className={styles.filePicker} role="group" aria-label="Optional source file">
            <div className={styles.fileDescription}>
              <Subtitle2>Or choose a file</Subtitle2>
              <Body2 className={styles.muted}>
                {sourceFile
                  ? `${sourceFile.name} · ${formatBytes(sourceFile.size)}`
                  : 'PDF, Office, code, and text files up to 1 MiB.'}
              </Body2>
            </div>
            <Button
              appearance="secondary"
              icon={<Attach24Regular />}
              onClick={() => fileInputRef.current?.click()}
            >
              Browse files
            </Button>
            <input
              ref={fileInputRef}
              className={styles.hiddenInput}
              type="file"
              aria-label="Choose a file to encrypt"
              accept=".pdf,.xls,.xlsx,.xlsm,.doc,.docx,.docm,.lua,.luau,.txt,.js,.mjs,.cjs,.sh,.bash,.zsh,.command,.cs,.bat,.cmd,.ps1,.psm1,.py,.json,.csv,.xml,.html,.css,.sql,.md"
              onChange={handleFileChange}
            />
          </div>
        </div>

        <div className={styles.fieldStack}>
          <Field label="Password" required hint="Use a unique passphrase with at least 16 characters.">
            <Input
              type="password"
              value={password}
              onChange={(_, data) => onPasswordChange(data.value)}
              autoComplete="new-password"
              required
              placeholder="Enter a strong passphrase"
            />
          </Field>
          <Field label="Confirm password" required hint="There is no password recovery.">
            <Input
              type="password"
              value={confirmation}
              onChange={(_, data) => onConfirmationChange(data.value)}
              autoComplete="new-password"
              required
              placeholder="Re-enter your passphrase"
            />
          </Field>
          <div className={styles.footer}>
            <Button
              appearance="primary"
              size="large"
              icon={<LockClosed24Regular />}
              disabled={isEncrypting}
              onClick={onEncrypt}
            >
              {isEncrypting ? 'Encrypting…' : 'Encrypt'}
            </Button>
            <Button
              appearance="subtle"
              icon={<Delete24Regular />}
              disabled={isEncrypting}
              onClick={handleClear}
            >
              Clear form
            </Button>
          </div>
        </div>
      </div>

      <div className={styles.feedback}>
        <FeedbackMessage feedback={feedback} />
      </div>

      {result && (
        <Card className={styles.resultCard}>
          <CardHeader
            header={<Subtitle2 as="h3">Encrypted chess notation</Subtitle2>}
            description={
              <Caption1>
                {result.bytes.length.toLocaleString()} moves · {formatBytes(result.bytes.length)}
              </Caption1>
            }
            action={
              <Button appearance="secondary" icon={<Copy24Regular />} onClick={onCopyPgn}>
                Copy PGN
              </Button>
            }
          />
          <Field label="PGN output" hint="This notation contains encrypted data, not readable source code.">
            <Textarea
              value={result.pgn}
              readOnly
              rows={8}
              resize="vertical"
              className={styles.codeArea}
            />
          </Field>
          <CardFooter className={styles.resultActions}>
            <Button appearance="secondary" icon={<ArrowDownload24Regular />} onClick={onDownloadCcx}>
              Download .ccx
            </Button>
            <Button appearance="secondary" icon={<ArrowDownload24Regular />} onClick={onDownloadPage}>
              Download protected HTML
            </Button>
          </CardFooter>
        </Card>
      )}
    </section>
  );
}
