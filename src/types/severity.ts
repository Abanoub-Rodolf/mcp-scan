export const SeverityLevel = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
} as const;

export type Severity = typeof SeverityLevel[keyof typeof SeverityLevel];

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

// Canonical severity palette. Every surface (CLI, HTML, dashboard, spinner)
// derives its colors from here so a finding renders the same hue everywhere.
export const BRAND_COLOR = '#339DFF';

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#F85149',
  HIGH: '#F0883E',
  MEDIUM: '#D29922',
  LOW: '#3FB949',
  INFO: '#8B949E',
};
