export const SOC2_MAPPING = {
  id: 'soc2',
  name: 'SOC 2 Type II (Security, Availability, Confidentiality)',
  controls: [
    { id: 'CC6.1', description: 'Logical Access Control', findingIds: ['exposed-secret', 'credential-relay-risk', 'env-var-scope-leak', 'exposed-secret'] },
    { id: 'CC6.6', description: 'Boundary Protection', findingIds: ['known-malicious', 'typosquat-detection', 'known-vulnerability-critical', 'known-vulnerability-high', 'prompt-injection-pattern', 'tool-name-shadow', 'supply-chain-low-trust'] },
    { id: 'CC6.7', description: 'Transmission Protection', findingIds: ['network-egress-obfuscated', 'network-egress-raw-ip', 'data-exfiltration-risk', 'data-controls-encryption-gap', 'insecure-transport', 'insecure-transport'] },
    { id: 'CC7.2', description: 'Security Monitoring', findingIds: ['network-egress-unknown', 'network-egress-suspicious', 'data-controls-prompt-logging', 'network-egress-data-in-url'] },
    { id: 'CC8.1', description: 'Change Management', findingIds: ['server-mutation', 'duplicate-server', 'server-mutation'] },
    { id: 'CC9.1', description: 'Risk Mitigation', findingIds: ['known-malicious', 'supply-chain-low-trust', 'typosquat-detection', 'known-vulnerability-critical'] },
    { id: 'A1.1', description: 'Availability Commitments', findingIds: ['network-egress-unknown', 'data-exfiltration-risk'] }
  ]
};
