'use client';

import {
  MessageBar,
  MessageBarBody,
  MessageBarTitle,
} from '@fluentui/react-components';

export function FeedbackMessage({ feedback }) {
  if (!feedback) return null;

  return (
    <div
      aria-live={feedback.intent === 'error' ? 'assertive' : 'polite'}
      aria-atomic="true"
    >
      <MessageBar intent={feedback.intent}>
        <MessageBarBody>
          <MessageBarTitle>{feedback.title}</MessageBarTitle>
          {feedback.message}
        </MessageBarBody>
      </MessageBar>
    </div>
  );
}
