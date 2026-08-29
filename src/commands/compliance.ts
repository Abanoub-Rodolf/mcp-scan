import { COMPLIANCE_FRAMEWORKS, getFramework } from '../data/compliance/index.js';
import { runScan } from './scan.js';
import { Finding } from '../types/scan-result.js';
import chalk from 'chalk';
import { proHint } from '../utils/pro-hint.js';
import fs from 'fs';

type ComplianceControl = { id: string; description: string; findingIds: string[] };
type ComplianceFramework = { id: string; name: string; controls: ComplianceControl[] };

export type ControlStatus = 'COMPLIANT' | 'PARTIAL' | 'NON-COMPLIANT';

export interface AssessedControl {
  id: string;
  description: string;
  findingsCount: number;
  status: ControlStatus;
  findings: Array<{ id: string; severity: string; description: string }>;
}

export interface FrameworkAssessment {
  name: string;
  score: number;
  controls: AssessedControl[];
  totalViolations: number;
}

export function controlStatus(count: number): ControlStatus {
  if (count === 0) return 'COMPLIANT';
  return count > 2 ? 'NON-COMPLIANT' : 'PARTIAL';
}

/** One assessment pass over a framework; every renderer consumes this. */
export function assessFramework(fw: ComplianceFramework, allFindings: Finding[]): FrameworkAssessment {
  const controls: AssessedControl[] = fw.controls.map(c => {
    const matching = allFindings.filter((f: Finding) => c.findingIds.includes(f.id));
    return {
      id: c.id,
      description: c.description,
      findingsCount: matching.length,
      status: controlStatus(matching.length),
      findings: matching.map((f: Finding) => ({
        id: f.id,
        severity: f.severity,
        description: f.description || 'No description provided',
      })),
    };
  });
  const compliantCount = controls.filter(c => c.status === 'COMPLIANT').length;
  return {
    name: fw.name,
    score: controls.length === 0 ? 0 : Math.round((compliantCount / controls.length) * 100),
    controls,
    totalViolations: controls.reduce((sum, c) => sum + c.findingsCount, 0),
  };
}

function renderConsole(a: FrameworkAssessment): string {
  let out = `\n${chalk.hex('#FFB833').bold('-- ' + a.name + ' Compliance Report --')}\n\n`;

  const scoreColor = a.score > 90 ? chalk.green : a.score > 70 ? chalk.yellow : chalk.red;
  out += `Overall Compliance Score: ${scoreColor.bold(a.score + '%')}\n`;
  out += `Summary: ${a.controls.filter(c => c.status === 'COMPLIANT').length} / ${a.controls.length} controls meeting criteria. ${a.totalViolations} total violations.\n\n`;

  for (const control of a.controls) {
    const statusColor = control.status === 'NON-COMPLIANT' ? chalk.red : control.status === 'PARTIAL' ? chalk.yellow : chalk.green;
    out += `${chalk.bold(control.id.padEnd(10))} ${control.description.substring(0, 40).padEnd(42)} ${statusColor(`[${control.status}]`)} (${control.findingsCount} findings)\n`;
    if (control.findingsCount > 0) {
      control.findings.slice(0, 3).forEach(f => {
        out += chalk.dim(`           └─ ${f.id}: ${f.description.substring(0, 60)}...\n`);
      });
    }
  }
  return out;
}

function toCsv(assessments: FrameworkAssessment[]): string {
  let csv = 'Framework,ControlID,Description,FindingsCount,Status\n';
  for (const a of assessments) {
    for (const c of a.controls) {
      csv += `"${a.name}","${c.id}","${c.description}",${c.findingsCount},"${c.status}"\n`;
    }
  }
  return csv;
}

function toJson(assessments: FrameworkAssessment[]): unknown {
  // Shape kept identical to the pre-refactor output for consumers.
  return assessments.map(a => ({
    name: a.name,
    complianceScore: a.score,
    controls: a.controls.map(c => ({
      id: c.id,
      description: c.description,
      findingsCount: c.findingsCount,
      compliant: c.status === 'COMPLIANT',
      findings: c.findings.map(f => ({ id: f.id, severity: f.severity })),
    })),
  }));
}

function toMarkdown(assessments: FrameworkAssessment[], generatedAt: string): string {
  let md = `# Compliance Framework Mapping Report\n\nGenerated: ${generatedAt}\n\n`;
  for (const a of assessments) {
    md += `## ${a.name}\n\n`;
    md += `**Compliance Score:** ${a.score}%\n\n`;
    md += `| Control | Description | Status | Findings |\n| --- | --- | --- | --- |\n`;
    for (const c of a.controls) {
      const status = c.status === 'NON-COMPLIANT' ? '🔴 NON-COMPLIANT' : c.status === 'PARTIAL' ? '🟡 PARTIAL' : '🟢 COMPLIANT';
      md += `| ${c.id} | ${c.description} | ${status} | ${c.findingsCount} |\n`;
    }
    md += '\n';
  }
  return md;
}

export async function runCompliance(options: { framework: string, output?: string }) {
    const frameworksToRun = (options.framework === 'all'
        ? COMPLIANCE_FRAMEWORKS
        : [getFramework(options.framework)]).filter((fw): fw is NonNullable<typeof fw> => !!fw);

    const AVAILABLE_FRAMEWORKS = ['soc2', 'gdpr', 'hipaa', 'pci-dss', 'nist', 'all'];
    if (frameworksToRun.length === 0) {
        console.error(chalk.red(`Error: Unknown framework '${options.framework}'.`));
        console.log(`Available: ${AVAILABLE_FRAMEWORKS.join(', ')}`);
        process.exitCode = 1;
        return;
    }

    const report = await runScan({ silent: true });
    const allFindings = report.results.flatMap(r => r.findings);
    const assessments = frameworksToRun.map(fw => assessFramework(fw, allFindings));

    if (options.output) {
        if (options.output.endsWith('.csv')) {
            fs.writeFileSync(options.output, toCsv(assessments));
            console.log(`Saved compliance CSV report to ${options.output}`);
        } else if (options.output.endsWith('.json')) {
            fs.writeFileSync(options.output, JSON.stringify(toJson(assessments), null, 2));
            console.log(`Saved compliance JSON report to ${options.output}`);
        } else {
            fs.writeFileSync(options.output, toMarkdown(assessments, new Date().toISOString()));
            console.log(`Saved compliance Markdown report to ${options.output}`);
        }
    } else {
        let fullOutput = '';
        for (const a of assessments) {
            fullOutput += renderConsole(a);
        }
        console.log(fullOutput);
        proHint();
    }
}
