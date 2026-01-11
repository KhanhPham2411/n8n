#!/usr/bin/env node
/**
 * This script creates a GitHub release for the portable version of n8n.
 * It creates a release with the portable zip file attached.
 */

import { $, echo, fs, chalk } from 'zx';
import path from 'path';

// Disable verbose output and force color only if not in CI
const isCI = process.env.CI === 'true';
$.verbose = !isCI;
process.env.FORCE_COLOR = isCI ? '0' : '1';

const scriptDir = path.dirname(new URL(import.meta.url).pathname);
const isInScriptsDir = path.basename(scriptDir) === 'scripts';
const rootDir = isInScriptsDir ? path.join(scriptDir, '..') : scriptDir;

// #region ===== Configuration =====
const config = {
	rootDir: rootDir,
	packageJsonPath: path.join(rootDir, 'package.json'),
};

// #endregion ===== Configuration =====

// #region ===== Helper Functions =====
function printHeader(title) {
	echo('');
	echo(chalk.blue.bold(`===== ${title} =====`));
}

function printDivider() {
	echo(chalk.gray('-----------------------------------------------'));
}

async function getVersion() {
	const packageJson = await fs.readJson(config.packageJsonPath);
	return packageJson.version;
}

async function checkGitHubCLI() {
	try {
		await $`gh --version`;
		return true;
	} catch (error) {
		return false;
	}
}

async function checkGitHubAuth() {
	try {
		await $`gh auth status`;
		return true;
	} catch (error) {
		return false;
	}
}

async function getCurrentBranch() {
	const result = await $`git branch --show-current`;
	return result.stdout.trim();
}

async function getRepoInfo() {
	try {
		// Get the origin remote URL from git
		const remoteUrl = await $`git remote get-url origin`;
		const url = remoteUrl.stdout.trim();

		// Extract owner/repo from URL
		// Supports both HTTPS and SSH formats
		const match = url.match(/github\.com[:/](.+?\/.+?)(?:\.git)?$/);
		if (match) {
			return match[1];
		}

		// Fallback to gh CLI if git remote parsing fails
		const result = await $`gh repo view --json nameWithOwner -q .nameWithOwner`;
		return result.stdout.trim();
	} catch (error) {
		echo(chalk.yellow('⚠️  Could not determine repository info'));
		return null;
	}
}

// #endregion ===== Helper Functions =====

// #region ===== Main Release Process =====
printHeader('n8n Portable GitHub Release');
printDivider();

// 1. Check prerequisites
echo(chalk.yellow('INFO: Checking prerequisites...'));

const hasGH = await checkGitHubCLI();
if (!hasGH) {
	echo(chalk.red('ERROR: GitHub CLI (gh) is not installed.'));
	echo(chalk.yellow('Install it from: https://cli.github.com/'));
	process.exit(1);
}

const isAuthenticated = await checkGitHubAuth();
if (!isAuthenticated) {
	echo(chalk.red('ERROR: GitHub CLI is not authenticated.'));
	echo(chalk.yellow('Run: gh auth login'));
	process.exit(1);
}

echo(chalk.green('✅ GitHub CLI is installed and authenticated'));
printDivider();

// 2. Get version and archive information
const version = await getVersion();
const archiveName = `n8n-atom-portable-${version}.zip`;
const archivePath = path.join(rootDir, archiveName);

echo(chalk.yellow(`INFO: Version: ${version}`));
echo(chalk.yellow(`INFO: Archive: ${archiveName}`));

// Check if archive exists
if (!(await fs.pathExists(archivePath))) {
	echo(chalk.red(`ERROR: Portable archive not found: ${archivePath}`));
	echo(chalk.yellow('Run: pnpm build:portable'));
	process.exit(1);
}

const archiveSize = (await $`du -h ${archivePath} | cut -f1`).stdout.trim();
echo(chalk.green(`✅ Archive found: ${archiveSize}`));
printDivider();

// 3. Get repository and branch info
const repoInfo = await getRepoInfo();
const currentBranch = await getCurrentBranch();

if (repoInfo) {
	echo(chalk.yellow(`INFO: Repository: ${repoInfo}`));
}
echo(chalk.yellow(`INFO: Current branch: ${currentBranch}`));
printDivider();

// 4. Determine release tag and title
const releaseTag = process.env.RELEASE_TAG || `portable-v${version}`;
const releaseTitle = process.env.RELEASE_TITLE || `n8n Portable v${version}`;
const isDraft = process.env.DRAFT_RELEASE === 'true';
const isPrerelease = process.env.PRERELEASE === 'true';

echo(chalk.yellow(`INFO: Release tag: ${releaseTag}`));
echo(chalk.yellow(`INFO: Release title: ${releaseTitle}`));
echo(chalk.yellow(`INFO: Draft: ${isDraft}`));
echo(chalk.yellow(`INFO: Prerelease: ${isPrerelease}`));
printDivider();

// 5. Generate release notes
echo(chalk.yellow('INFO: Generating release notes...'));

const releaseNotes =
	process.env.RELEASE_NOTES ||
	`
# n8n Portable v${version}

This is a portable, offline-capable version of n8n-atom. It includes all dependencies and can run without an internet connection.

## What's Included

- ✅ Self-contained n8n installation
- ✅ All runtime dependencies bundled
- ✅ Cross-platform startup scripts (Unix/Windows)
- ✅ No internet required after download
- ✅ No build tools needed (npm/pnpm/yarn)

## System Requirements

- **Node.js**: Version 20.19 or higher (up to 24.x)
- **Disk Space**: ~500MB
- **Platform**: Unix/Linux/macOS/Windows

## Quick Start

### Unix/Linux/macOS

\`\`\`bash
unzip ${archiveName}
cd n8n-atom-portable
./n8n start
\`\`\`

### Windows

\`\`\`cmd
unzip ${archiveName}
cd n8n-atom-portable
n8n.cmd start
\`\`\`

## Documentation

For detailed instructions, see [PORTABLE.md](https://github.com/${repoInfo || 'KhanhPham2411/n8n-atom'}/blob/${currentBranch}/PORTABLE.md)

## What's New

Check the [CHANGELOG.md](https://github.com/${repoInfo || 'KhanhPham2411/n8n-atom'}/blob/${currentBranch}/CHANGELOG.md) for details.

## Support

- **Documentation**: https://docs.n8n.io
- **Community Forum**: https://community.n8n.io
- **Issues**: https://github.com/${repoInfo || 'KhanhPham2411/n8n-atom'}/issues
`;

// Save release notes to file for review
const releaseNotesPath = path.join(rootDir, 'release-notes.md');
await fs.writeFile(releaseNotesPath, releaseNotes);
echo(chalk.green(`✅ Release notes saved to: ${releaseNotesPath}`));
printDivider();

// 6. Confirm release creation
if (!isCI && process.env.SKIP_CONFIRM !== 'true') {
	echo(chalk.yellow(''));
	echo(chalk.yellow('📋 Release Summary:'));
	echo(chalk.yellow(`   Tag:         ${releaseTag}`));
	echo(chalk.yellow(`   Title:       ${releaseTitle}`));
	echo(chalk.yellow(`   Branch:      ${currentBranch}`));
	echo(chalk.yellow(`   Archive:     ${archiveName} (${archiveSize})`));
	echo(chalk.yellow(`   Draft:       ${isDraft}`));
	echo(chalk.yellow(`   Prerelease:  ${isPrerelease}`));
	echo(chalk.yellow(''));

	const readline = (await import('readline')).default;
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
	});

	const answer = await new Promise((resolve) => {
		rl.question(chalk.cyan('Create this release? (y/N): '), (answer) => {
			rl.close();
			resolve(answer);
		});
	});

	if (answer.toLowerCase() !== 'y' && answer.toLowerCase() !== 'yes') {
		echo(chalk.yellow('Release creation cancelled.'));
		process.exit(0);
	}
}

printDivider();

// 7. Create GitHub release
echo(chalk.yellow('INFO: Creating GitHub release...'));

try {
	const createArgs = [
		'release',
		'create',
		releaseTag,
		archivePath,
		'--title',
		releaseTitle,
		'--notes-file',
		releaseNotesPath,
	];

	if (isDraft) {
		createArgs.push('--draft');
	}

	if (isPrerelease) {
		createArgs.push('--prerelease');
	}

	// Add target branch/commit if specified
	if (process.env.TARGET_COMMITISH) {
		createArgs.push('--target', process.env.TARGET_COMMITISH);
	}

	await $`gh ${createArgs}`;

	echo('');
	echo(chalk.green.bold('================ RELEASE CREATED SUCCESSFULLY ================'));
	echo(chalk.green(`✅ GitHub release created: ${releaseTag}`));
	echo('');
	echo(chalk.blue('📦 Release Details:'));
	echo(`   Tag:         ${releaseTag}`);
	echo(`   Title:       ${releaseTitle}`);
	echo(`   Archive:     ${archiveName} (${archiveSize})`);
	echo(`   Draft:       ${isDraft}`);
	echo(`   Prerelease:  ${isPrerelease}`);
	echo('');
	echo(chalk.blue('🔗 View Release:'));
	if (repoInfo) {
		echo(`   https://github.com/${repoInfo}/releases/tag/${releaseTag}`);
	}
	echo('');
	echo(chalk.green.bold('============================================================='));
	echo('');

	// Clean up release notes file
	await fs.remove(releaseNotesPath);
} catch (error) {
	echo('');
	echo(chalk.red.bold('================ RELEASE CREATION FAILED ================'));
	echo(chalk.red('❌ Failed to create GitHub release'));
	echo('');
	echo(chalk.yellow('Error details:'));
	echo(error.message);
	echo('');

	if (error.stderr) {
		echo(chalk.yellow('Error output:'));
		echo(error.stderr);
		echo('');
	}

	echo(chalk.yellow('💡 Troubleshooting:'));
	echo('   1. Check if the tag already exists: gh release view ' + releaseTag);
	echo('   2. Ensure you have push permissions to the repository');
	echo('   3. Verify GitHub authentication: gh auth status');
	echo('   4. Try creating a draft first: DRAFT_RELEASE=true pnpm release:portable');
	echo('');
	echo(chalk.red.bold('========================================================'));
	echo('');

	process.exit(1);
}

// #endregion ===== Main Release Process =====

process.exit(0);
