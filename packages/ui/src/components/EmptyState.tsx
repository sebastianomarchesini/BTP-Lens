import '@ui5/webcomponents-fiori/dist/illustrations/NoData.js';
import '@ui5/webcomponents-fiori/dist/illustrations/NoEntries.js';
import '@ui5/webcomponents-fiori/dist/illustrations/NoFilterResults.js';
import { IllustratedMessage } from '@ui5/webcomponents-react';

interface EmptyStateProps {
  name: 'NoData' | 'NoEntries' | 'NoFilterResults';
  title: string;
  subtitle: string;
  /** "Spot" inside cards, "Auto" on full pages. */
  design?: 'Auto' | 'Spot' | 'Dot';
}

export function EmptyState({ name, title, subtitle, design = 'Auto' }: EmptyStateProps) {
  return (
    <IllustratedMessage name={name} design={design} titleText={title} subtitleText={subtitle} />
  );
}
