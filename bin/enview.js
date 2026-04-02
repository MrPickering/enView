#!/usr/bin/env node

import { Command } from 'commander';
import { scanDirectories, addGitignoreEntry } from '../src/scanner.js';
import {
  printScanResults,
  printAuditResults,
  printKeysResults,
  printDriftResults,
  printFixResults,
} from '../src/reporter.js';

const program = new Command();

program
  .name('enview')
  .description('Cross-project .env scanner, auditor, and drift detector.\nKnow what secrets live where — without exposing them.')
  .version('0.1.0');

program
  .command('scan')
  .description('Find and inventory all .env files across project directories')
  .argument('[dirs...]', 'Directories to scan (default: current directory)', ['.'])
  .option('-d, --depth <n>', 'Max directory depth', parseInt, 6)
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const projects = scanDirectories(dirs.length ? dirs : ['.'], { maxDepth: opts.depth });
    printScanResults(projects, opts);
  });

program
  .command('audit')
  .description('Security audit — find plaintext secrets, missing .gitignore, exposed keys')
  .argument('[dirs...]', 'Directories to scan', ['.'])
  .option('-d, --depth <n>', 'Max directory depth', parseInt, 6)
  .option('--json', 'Output as JSON (for CI integration)')
  .option('--strict', 'Exit with code 1 on any critical finding')
  .action((dirs, opts) => {
    const projects = scanDirectories(dirs.length ? dirs : ['.'], { maxDepth: opts.depth });
    printAuditResults(projects, opts);

    if (opts.strict) {
      const hasCritical = projects.some(p =>
        p.files.some(f => f.sensitiveKeys.length > 0 || (!f.gitIgnored && f.encryption.type === 'none' && f.inGitRepo))
      );
      if (hasCritical) process.exit(1);
    }
  });

program
  .command('keys')
  .description('List all key names across projects (values are NEVER shown)')
  .argument('[dirs...]', 'Directories to scan', ['.'])
  .option('-d, --depth <n>', 'Max directory depth', parseInt, 6)
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const projects = scanDirectories(dirs.length ? dirs : ['.'], { maxDepth: opts.depth });
    printKeysResults(projects, opts);
  });

program
  .command('drift')
  .description('Compare keys across environments — find missing variables')
  .argument('[dirs...]', 'Directories to scan', ['.'])
  .option('-d, --depth <n>', 'Max directory depth', parseInt, 6)
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const projects = scanDirectories(dirs.length ? dirs : ['.'], { maxDepth: opts.depth });
    printDriftResults(projects, opts);
  });

program
  .command('fix')
  .description('Add missing .gitignore entries and show encryption commands')
  .argument('[dirs...]', 'Directories to scan', ['.'])
  .option('-d, --depth <n>', 'Max directory depth', parseInt, 6)
  .option('--dry-run', 'Show what would be fixed without making changes')
  .action((dirs, opts) => {
    const projects = scanDirectories(dirs.length ? dirs : ['.'], { maxDepth: opts.depth });
    const fixActions = { gitignoreAdded: [], alreadyIgnored: [] };

    for (const project of projects) {
      for (const f of project.files) {
        if (!f.inGitRepo) continue;
        if (f.gitIgnored) {
          fixActions.alreadyIgnored.push({ project: project.name, fileName: f.fileName });
          continue;
        }
        if (opts.dryRun) {
          fixActions.gitignoreAdded.push({ project: project.name, fileName: f.fileName, dryRun: true });
        } else {
          const added = addGitignoreEntry(project.path, f.fileName);
          if (added) {
            fixActions.gitignoreAdded.push({ project: project.name, fileName: f.fileName });
          } else {
            fixActions.alreadyIgnored.push({ project: project.name, fileName: f.fileName });
          }
        }
      }
    }

    printFixResults(projects, fixActions);
  });

program.parse();
