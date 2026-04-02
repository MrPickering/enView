#!/usr/bin/env node

import { Command } from 'commander';
import os from 'node:os';
import chalk from 'chalk';
import { scanDirectories, addGitignoreEntry, getAutoRoots, getSystemRoots } from '../src/scanner.js';
import {
  printScanResults,
  printAuditResults,
  printKeysResults,
  printDriftResults,
  printFixResults,
} from '../src/reporter.js';

function resolveRoots(dirs, opts) {
  if (opts.system) {
    const roots = getSystemRoots();
    console.log(chalk.dim(`\n  Scanning system drives: ${roots.join(', ')}\n`));
    return { roots, scanOpts: { maxDepth: opts.depth ?? 8, broad: true } };
  }
  if (!dirs.length) {
    const roots = getAutoRoots();
    console.log(chalk.dim(`\n  Scanning home directory: ${roots[0]}\n`));
    return { roots, scanOpts: { maxDepth: opts.depth ?? 5, broad: true } };
  }
  return { roots: dirs, scanOpts: { maxDepth: opts.depth ?? 6 } };
}

const program = new Command();

program
  .name('enview')
  .description('Cross-project .env scanner, auditor, and drift detector.\nKnow what secrets live where — without exposing them.')
  .version('0.1.0');

program
  .command('scan')
  .description('Find and inventory all .env files across project directories')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printScanResults(projects, opts);
  });

program
  .command('audit')
  .description('Security audit — find plaintext secrets, missing .gitignore, exposed keys')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON (for CI integration)')
  .option('--strict', 'Exit with code 1 on any critical finding')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
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
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printKeysResults(projects, opts);
  });

program
  .command('drift')
  .description('Compare keys across environments — find missing variables')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--json', 'Output as JSON')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
    printDriftResults(projects, opts);
  });

program
  .command('fix')
  .description('Add missing .gitignore entries and show encryption commands')
  .argument('[dirs...]', 'Directories to scan (default: home directory)')
  .option('-d, --depth <n>', 'Max directory depth', parseInt)
  .option('--system', 'Scan all system drives')
  .option('--dry-run', 'Show what would be fixed without making changes')
  .action((dirs, opts) => {
    const { roots, scanOpts } = resolveRoots(dirs, opts);
    const projects = scanDirectories(roots, scanOpts);
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
