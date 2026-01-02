#!/usr/bin/env node
/**
 * This script builds a portable version of n8n that can run without internet.
 * It creates a self-contained package with all dependencies bundled.
 */

import { $, echo, fs, chalk } from 'zx';
import path from 'path';
import { createWriteStream } from 'fs';

// Disable verbose output and force color only if not in CI
const isCI = process.env.CI === 'true';
$.verbose = !isCI;
process.env.FORCE_COLOR = isCI ? '0' : '1';

const scriptDir = path.dirname(new URL(import.meta.url).pathname);
const isInScriptsDir = path.basename(scriptDir) === 'scripts';
const rootDir = isInScriptsDir ? path.join(scriptDir, '..') : scriptDir;

// #region ===== Configuration =====
const config = {
	compiledAppDir: path.join(rootDir, 'compiled'),
	portableDir: path.join(rootDir, 'n8n-atom-portable'),
	rootDir: rootDir,
	cliDir: path.join(rootDir, 'packages', 'cli'),
};

// #endregion ===== Configuration =====

// #region ===== Helper Functions =====
const timers = new Map();

function startTimer(name) {
	timers.set(name, Date.now());
}

function getElapsedTime(name) {
	const start = timers.get(name);
	if (!start) return 0;
	return Math.floor((Date.now() - start) / 1000);
}

function formatDuration(seconds) {
	const hours = Math.floor(seconds / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	const secs = seconds % 60;

	if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
	if (minutes > 0) return `${minutes}m ${secs}s`;
	return `${secs}s`;
}

function printHeader(title) {
	echo('');
	echo(chalk.blue.bold(`===== ${title} =====`));
}

function printDivider() {
	echo(chalk.gray('-----------------------------------------------'));
}

// #endregion ===== Helper Functions =====

// #region ===== Main Build Process =====
printHeader('n8n Portable Build');
echo(`INFO: Output Directory: ${config.portableDir}`);
printDivider();

startTimer('total_build');

// 0. Check if compiled version exists
if (!(await fs.pathExists(config.compiledAppDir))) {
	echo(chalk.red('ERROR: Compiled version not found. Please run "pnpm build:n8n" first.'));
	process.exit(1);
}

// 1. Clean previous portable build
echo(chalk.yellow(`INFO: Cleaning previous portable build: ${config.portableDir}...`));
await fs.remove(config.portableDir);
await fs.ensureDir(config.portableDir);
printDivider();

// 2. Copy compiled application
echo(chalk.yellow('INFO: Copying compiled application...'));
startTimer('copy_files');
await fs.copy(config.compiledAppDir, config.portableDir, {
	filter: (src) => {
		// Exclude node_modules from compiled if they exist (we'll use the full ones)
		if (src.includes('node_modules') && src !== config.compiledAppDir) {
			return false;
		}
		// Exclude bin directory - we'll create our own portable startup scripts
		if (src.includes('/bin/') || src.endsWith('/bin')) {
			return false;
		}
		return true;
	},
});
echo(chalk.green('✅ Compiled application copied'));

// 3. Ensure node_modules exists in compiled (it should from pnpm deploy)
const compiledNodeModules = path.join(config.compiledAppDir, 'node_modules');
if (await fs.pathExists(compiledNodeModules)) {
	echo(chalk.yellow('INFO: Copying node_modules...'));
	await fs.copy(compiledNodeModules, path.join(config.portableDir, 'node_modules'));
	echo(chalk.green('✅ node_modules copied'));
} else {
	echo(chalk.yellow('⚠️  Warning: node_modules not found in compiled directory'));
}

const copyTime = getElapsedTime('copy_files');
echo(chalk.green(`✅ Files copied in ${formatDuration(copyTime)}`));
printDivider();

// 4. Create portable startup scripts
echo(chalk.yellow('INFO: Creating portable startup scripts...'));

// Unix startup script
const unixStartScript = `#!/usr/bin/env node

const path = require('path');
const Module = require('module');

// Get the directory where this script is located
const scriptDir = path.dirname(__filename);
const portableDir = path.resolve(scriptDir);

// Set NODE_PATH to use local node_modules
const nodeModulesPath = path.join(portableDir, 'node_modules');
if (process.env.NODE_PATH) {
	process.env.NODE_PATH = nodeModulesPath + path.delimiter + process.env.NODE_PATH;
} else {
	process.env.NODE_PATH = nodeModulesPath;
}
Module._initPaths();

// Override require.resolve to ensure n8n package resolves to portable directory
// This fixes module loading in the portable version
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
	// If trying to resolve 'n8n/package.json', redirect to portable directory
	if (request === 'n8n/package.json') {
		const portablePackageJson = path.join(portableDir, 'package.json');
		if (require('fs').existsSync(portablePackageJson)) {
			return portablePackageJson;
		}
	}
	return originalResolve.call(this, request, parent, isMain, options);
};

// Make sure that it also find the config folder when it
// did get started from another folder that the root one.
process.env.NODE_CONFIG_DIR = process.env.NODE_CONFIG_DIR || path.join(portableDir, 'config');

// Check if version should be displayed
const versionFlags = ['-v', '-V', '--version'];
if (versionFlags.includes(process.argv.slice(-1)[0])) {
	const packageJson = require(path.join(portableDir, 'package.json'));
	console.log(packageJson.version);
	process.exit(0);
}

const satisfies = require('semver/functions/satisfies');
const nodeVersion = process.versions.node;
const packageJson = require(path.join(portableDir, 'package.json'));
const supportedNodeVersions = packageJson.engines?.node || '>=20.19 <= 24.x';
if (!satisfies(nodeVersion, supportedNodeVersions)) {
	console.error(\`
Your Node.js version \${nodeVersion} is currently not supported by n8n.
Please use a Node.js version that satisfies the following version range: \${supportedNodeVersions}
\`);
	process.exit(1);
}

// Disable nodejs custom inspection across the app
const { inspect } = require('util');
inspect.defaultOptions.customInspect = false;

require('source-map-support').install();
require('reflect-metadata');

// Skip loading dotenv in e2e tests.
if (process.env.E2E_TESTS !== 'true') {
	require('dotenv').config({ quiet: true });
}

// Load config early
require(path.join(portableDir, 'dist', 'config'));

if (process.env.NODEJS_PREFER_IPV4 === 'true') {
	require('dns').setDefaultResultOrder('ipv4first');
}

require('net').setDefaultAutoSelectFamily?.(false);

(async () => {
	const { Container } = await import('@n8n/di');
	const { CommandRegistry } = await import(path.join(portableDir, 'dist', 'command-registry.js'));
	await Container.get(CommandRegistry).execute();
})();
`;

// Windows startup script
const windowsStartScript = `@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PORTABLE_DIR=%SCRIPT_DIR%"

REM Set NODE_PATH to use local node_modules
set "NODE_PATH=%PORTABLE_DIR%node_modules"

REM Change to portable directory
cd /d "%PORTABLE_DIR%"

REM Set NODE_CONFIG_DIR
if not defined NODE_CONFIG_DIR set "NODE_CONFIG_DIR=%PORTABLE_DIR%config"

REM Run n8n using node with the portable directory
node "%PORTABLE_DIR%start-portable.js" %*

endlocal
`;

// Windows JS launcher
const windowsJsLauncher = `const path = require('path');
const Module = require('module');

// Get the directory where this script is located
const scriptDir = path.dirname(__filename);
const portableDir = path.resolve(scriptDir);

// Set NODE_PATH to use local node_modules
const nodeModulesPath = path.join(portableDir, 'node_modules');
if (process.env.NODE_PATH) {
	process.env.NODE_PATH = nodeModulesPath + path.delimiter + process.env.NODE_PATH;
} else {
	process.env.NODE_PATH = nodeModulesPath;
}
Module._initPaths();

// Override require.resolve to ensure n8n package resolves to portable directory
// This fixes module loading in the portable version
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
	// If trying to resolve 'n8n/package.json', redirect to portable directory
	if (request === 'n8n/package.json') {
		const portablePackageJson = path.join(portableDir, 'package.json');
		if (require('fs').existsSync(portablePackageJson)) {
			return portablePackageJson;
		}
	}
	return originalResolve.call(this, request, parent, isMain, options);
};

// Make sure that it also find the config folder when it
// did get started from another folder that the root one.
process.env.NODE_CONFIG_DIR = process.env.NODE_CONFIG_DIR || path.join(portableDir, 'config');

// Check if version should be displayed
const versionFlags = ['-v', '-V', '--version'];
if (versionFlags.includes(process.argv.slice(-1)[0])) {
	const packageJson = require(path.join(portableDir, 'package.json'));
	console.log(packageJson.version);
	process.exit(0);
}

const satisfies = require('semver/functions/satisfies');
const nodeVersion = process.versions.node;
const packageJson = require(path.join(portableDir, 'package.json'));
const supportedNodeVersions = packageJson.engines?.node || '>=20.19 <= 24.x';
if (!satisfies(nodeVersion, supportedNodeVersions)) {
	console.error(\`
Your Node.js version \${nodeVersion} is currently not supported by n8n.
Please use a Node.js version that satisfies the following version range: \${supportedNodeVersions}
\`);
	process.exit(1);
}

// Disable nodejs custom inspection across the app
const { inspect } = require('util');
inspect.defaultOptions.customInspect = false;

require('source-map-support').install();
require('reflect-metadata');

// Skip loading dotenv in e2e tests.
if (process.env.E2E_TESTS !== 'true') {
	require('dotenv').config({ quiet: true });
}

// Load config early
require(path.join(portableDir, 'dist', 'config'));

if (process.env.NODEJS_PREFER_IPV4 === 'true') {
	require('dns').setDefaultResultOrder('ipv4first');
}

require('net').setDefaultAutoSelectFamily?.(false);

(async () => {
	const { Container } = await import('@n8n/di');
	const { CommandRegistry } = await import(path.join(portableDir, 'dist', 'command-registry.js'));
	await Container.get(CommandRegistry).execute();
})();
`;

// Write startup scripts
await fs.writeFile(path.join(config.portableDir, 'n8n'), unixStartScript);
await fs.writeFile(path.join(config.portableDir, 'n8n.cmd'), windowsStartScript);
await fs.writeFile(path.join(config.portableDir, 'start-portable.js'), windowsJsLauncher);

// Make Unix script executable
await $`chmod +x ${path.join(config.portableDir, 'n8n')}`;

echo(chalk.green('✅ Startup scripts created'));
printDivider();

// 5. Create README for portable version
echo(chalk.yellow('INFO: Creating README...'));

const readmeContent = `# n8n Portable Version

This is a portable, offline-capable version of n8n. It includes all dependencies and can run without an internet connection.

## Requirements

- Node.js version 20.19 or higher (up to 24.x)
- No internet connection required after initial setup

## Quick Start

### Unix/Linux/macOS

\`\`\`bash
./n8n start
\`\`\`

### Windows

\`\`\`cmd
n8n.cmd start
\`\`\`

Or double-click \`n8n.cmd\` in Windows Explorer.

## Usage

The portable version works exactly like the regular n8n installation. All commands are available:

- \`./n8n start\` - Start n8n server
- \`./n8n start --tunnel\` - Start with tunnel
- \`./n8n worker\` - Start as worker
- \`./n8n webhook\` - Start webhook server
- \`./n8n --version\` - Show version

## Configuration

n8n will create its data directory in:
- **Unix/Linux/macOS**: \`~/.n8n\`
- **Windows**: \`%APPDATA%\\\\n8n\`

You can override this by setting the \`N8N_USER_FOLDER\` environment variable.

## Environment Variables

You can set environment variables before running n8n:

\`\`\`bash
export N8N_PORT=5678
export N8N_HOST=0.0.0.0
./n8n start
\`\`\`

## Offline Usage

This portable version includes all dependencies and does not require:
- npm/pnpm/yarn
- Internet connection
- Package installation

Simply extract the archive and run the startup script.

## Troubleshooting

### Node.js Version

If you get a Node.js version error, make sure you have Node.js 20.19 or higher installed:

\`\`\`bash
node --version
\`\`\`

### Permissions (Unix/Linux/macOS)

If you get a permission denied error, make the script executable:

\`\`\`bash
chmod +x n8n
\`\`\`

### Port Already in Use

If port 5678 is already in use, you can change it:

\`\`\`bash
export N8N_PORT=5679
./n8n start
\`\`\`

## Distribution

This portable version can be:
- Copied to USB drives
- Distributed to air-gapped networks
- Used in environments without internet access
- Shared with team members who don't have npm/pnpm installed

## Support

For more information, visit:
- Documentation: https://docs.n8n.io
- Community Forum: https://community.n8n.io
`;

await fs.writeFile(path.join(config.portableDir, 'README.md'), readmeContent);
echo(chalk.green('✅ README created'));
printDivider();

// 6. Create package info
const packageJsonPath = path.join(config.compiledAppDir, 'package.json');
let packageJson = null;
if (await fs.pathExists(packageJsonPath)) {
	packageJson = await fs.readJson(packageJsonPath);
	packageJson.name = 'n8n-atom-portable';
	packageJson.description = 'Portable, offline-capable version of n8n';
	await fs.writeJson(path.join(config.portableDir, 'package.json'), packageJson, { spaces: 2 });
}

// 7. Calculate size
const portableSize = (await $`du -sh ${config.portableDir} | cut -f1`).stdout.trim();
echo(chalk.green(`✅ Portable version created: ${portableSize}`));
printDivider();

// 8. Create archive (optional)
let archiveTime = null;
let archiveName = null;
if (process.env.CREATE_ARCHIVE !== 'false') {
	try {
		// Try to import archiver dynamically
		const archiverModule = await import('archiver');
		const archiver = archiverModule.default || archiverModule;

		echo(chalk.yellow('INFO: Creating distribution archive...'));
		startTimer('create_archive');

		const packageJson = await fs.readJson(path.join(config.portableDir, 'package.json'));
		archiveName = `n8n-atom-portable-${packageJson?.version || 'unknown'}.zip`;
		const archivePath = path.join(rootDir, archiveName);

		await new Promise((resolve, reject) => {
			const output = createWriteStream(archivePath);
			const archive = archiver('zip', { zlib: { level: 9 } });

			output.on('close', () => {
				echo(chalk.green(`✅ Archive created: ${archiveName}`));
				resolve();
			});

			archive.on('error', (err) => reject(err));
			archive.pipe(output);
			archive.directory(config.portableDir, false);
			archive.finalize();
		});

		const archiveSize = (await $`du -sh ${archivePath} | cut -f1`).stdout.trim();
		archiveTime = getElapsedTime('create_archive');
		echo(chalk.green(`✅ Archive created in ${formatDuration(archiveTime)}: ${archiveSize}`));
	} catch (error) {
		echo(chalk.yellow('⚠️  Warning: Could not create archive (archiver not available)'));
		echo(chalk.gray('   You can manually create a zip/tar archive of the portable directory'));
	}
}

const totalBuildTime = getElapsedTime('total_build');

// #endregion ===== Main Build Process =====

// #region ===== Final Output =====
echo('');
echo(chalk.green.bold('================ PORTABLE BUILD SUMMARY ================'));
echo(chalk.green(`✅ n8n portable version built successfully!`));
echo('');
echo(chalk.blue('📦 Build Output:'));
echo(`   Directory:      ${path.resolve(config.portableDir)}`);
echo(`   Size:           ${portableSize}`);
if (archiveName) {
	echo(`   Archive:         ${path.resolve(rootDir, archiveName)}`);
}
echo('');
echo(chalk.blue('⏱️  Build Times:'));
echo(`   Copy Files:     ${formatDuration(copyTime)}`);
if (archiveTime !== null) {
	echo(`   Create Archive:  ${formatDuration(archiveTime)}`);
}
echo(chalk.gray('   -----------------------------'));
echo(chalk.bold(`   Total Time:     ${formatDuration(totalBuildTime)}`));
echo('');
echo(chalk.blue('📋 Usage:'));
echo(`   Unix/Linux/macOS:  cd ${config.portableDir} && ./n8n start`);
echo(`   Windows:           cd ${config.portableDir} && n8n.cmd start`);
echo('');
echo(chalk.green.bold('======================================================'));
echo('');
echo(chalk.yellow('💡 This portable version can run completely offline!'));
echo(chalk.yellow('   No npm/pnpm installation required.'));
echo('');

// #endregion ===== Final Output =====

// Exit with success
process.exit(0);

