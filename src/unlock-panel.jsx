'use client';

import { useRef } from 'react';
import {
  Body2,
  Button,
  Card,
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
  Attach24Regular,
  Copy24Regular,
  Delete24Regular,
  LockOpen24Regular,
} from '@fluentui/react-icons';
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
  resultText: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
});

export function UnlockPanel({
  source,
  fileName,
  onSourceChange,
  onFileSelect,
  password,
  onPasswordChange,
  onDecrypt,
  isDecrypting,
  feedback,
  result,
  onCopy,
  onClear,
}) {
  const styles = useStyles();
  const fileInputRef = useRef(null);

  function handleFileChange(event) {
    const file = event.currentTarget.files?.[0] ?? null;
    event.currentTarget.value = '';
    if (file) onFileSelect(file);
  }

  function handleSourceChange(value) {
    if (fileInputRef.current) fileInputRef.current.value = '';
    onSourceChange(value);
  }

  function handleClear() {
    if (fileInputRef.current) fileInputRef.current.value = '';
    onClear();
  }

  return (
    <section className={styles.panel} aria-labelledby="unlock-heading">
      <div className={styles.panelHeader}>
        <div className={styles.panelIntro}>
          <Subtitle2 as="h2" id="unlock-heading">Unlock a protected file</Subtitle2>
          <Body2 className={styles.muted}>Decrypt an encrypted chess score, CCX file, or protected HTML page.</Body2>
        </div>
        <Caption1>Legacy CCX files supported</Caption1>
      </div>

      <div className={styles.fieldStack}>
        <Field label="PGN or protected HTML" hint="Paste chess notation or load a .pgn, .txt, or protected HTML file.">
          <Textarea
            value={source}
            onChange={(_, data) => handleSourceChange(data.value)}
            placeholder={'Paste encrypted PGN or protected HTML here…\n\n[Event "Secret"]\n[Date "…"]\n\n1. Rh5 Nb3 2. …'}
            rows={9}
            resize="vertical"
            className={styles.codeArea}
          />
        </Field>

        <div className={styles.filePicker} role="group" aria-label="Optional encrypted file">
          <div className={styles.fileDescription}>
            <Subtitle2>Or choose an encrypted file</Subtitle2>
            <Body2 className={styles.muted}>
              {fileName || 'CCX, PGN, TXT, and protected HTML are supported.'}
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
            aria-label="Choose a file to decrypt"
            accept=".ccx,.pgn,.txt,.html,.htm"
            onChange={handleFileChange}
          />
        </div>

        <Field label="Password" required hint="Decryption accepts existing passwords of any length.">
          <Input
            type="password"
            value={password}
            onChange={(_, data) => onPasswordChange(data.value)}
            autoComplete="current-password"
            required
            placeholder="Enter the password shared with you"
          />
        </Field>

        <div className={styles.footer}>
          <Button
            appearance="primary"
            size="large"
            icon={<LockOpen24Regular />}
            disabled={isDecrypting}
            onClick={onDecrypt}
          >
            {isDecrypting ? 'Decrypting…' : 'Decrypt'}
          </Button>
          <Button
            appearance="subtle"
            icon={<Delete24Regular />}
            disabled={isDecrypting}
            onClick={handleClear}
          >
            Clear form
          </Button>
        </div>
      </div>

      <div className={styles.feedback}>
        <FeedbackMessage feedback={feedback} />
      </div>

      {result?.kind === 'text' && (
        <Card className={styles.resultCard}>
          <CardHeader
            header={<Subtitle2 as="h3">Decrypted code</Subtitle2>}
            description={<Caption1>{result.meta}</Caption1>}
            action={
              <Button appearance="secondary" icon={<Copy24Regular />} onClick={onCopy}>
                Copy code
              </Button>
            }
          />
          <div className={styles.resultText}>
            <Field label="Plaintext output">
              <Textarea
                value={result.code}
                readOnly
                rows={12}
                resize="vertical"
                className={styles.codeArea}
              />
            </Field>
          </div>
        </Card>
      )}
    </section>
  );
}
