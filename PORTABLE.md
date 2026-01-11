# n8n Portable Mode

## Overview

**Portable mode** in n8n-atom is a special build configuration that creates a self-contained, offline-capable version of n8n. This distribution includes all dependencies bundled together, allowing n8n to run without internet access and without requiring package managers like npm or pnpm.

## What is Portable Mode?

Portable mode creates a standalone distribution that:

- ✅ **Runs completely offline** - No internet connection required after initial setup
- ✅ **Self-contained** - All dependencies are bundled (node_modules included)
- ✅ **No build tools needed** - Works without npm, pnpm, or yarn
- ✅ **Cross-platform** - Supports Unix/Linux/macOS and Windows
- ✅ **Easy distribution** - Can be copied via USB drives or shared as a zip file
- ✅ **Air-gapped ready** - Perfect for secure, isolated networks

## Use Cases

The portable version is ideal for:

1. **Air-gapped environments** - Secure networks without internet access
2. **Quick demos** - Share with clients/team members who don't have Node.js tooling
3. **USB deployments** - Run n8n from a USB drive on any compatible system
4. **Offline development** - Work on n8n in locations without internet
5. **Simplified distribution** - Deploy to multiple machines without complex setup
6. **Testing environments** - Quickly spin up isolated n8n instances

## How It Works

### Architecture

The portable build process:

1. **Compiles the application** - Builds all TypeScript packages to JavaScript
2. **Bundles dependencies** - Copies all `node_modules` required for runtime
3. **Creates startup scripts** - Generates platform-specific launchers (Unix/Windows)
4. **Packages everything** - Optionally creates a zip archive for distribution

### Key Components

The portable distribution includes:

```
n8n-atom-portable/
├── n8n                    # Unix/Linux/macOS startup script
├── n8n.cmd                # Windows batch file launcher
├── start-portable.js      # Windows JavaScript launcher
├── package.json           # Modified package metadata
├── README.md              # Quick start guide
├── dist/                  # Compiled JavaScript code
├── node_modules/          # All runtime dependencies
├── templates/             # Email and form templates
└── config/                # Configuration files
```

## Building Portable Mode

### Prerequisites

Before building a portable version, ensure you have:

- **Node.js**: Version 20.19 or higher (up to 24.x)
- **pnpm**: Version 10.22.0 or higher
- All project dependencies installed

### Build Commands

#### Standard Build

Build n8n in portable mode with archive creation:

```bash
# From the project root
pnpm build:portable
```

This command:
1. Runs `node scripts/build-n8n.mjs` - Compiles the application
2. Runs `node scripts/build-portable.mjs` - Creates the portable distribution

#### Build Without Archive

If you want to skip zip archive creation:

```bash
# Build the compiled version first
pnpm build:n8n

# Create portable version without archive
CREATE_ARCHIVE=false node scripts/build-portable.mjs
```

### Build Process Details

The build process executes these steps:

1. **Validates compiled version** - Checks if `compiled/` directory exists
2. **Cleans previous build** - Removes old `n8n-atom-portable/` directory
3. **Copies compiled app** - Transfers all files from `compiled/` to portable directory
4. **Copies node_modules** - Includes all runtime dependencies
5. **Creates startup scripts** - Generates platform-specific launchers
6. **Creates README** - Adds usage documentation
7. **Modifies package.json** - Updates metadata for portable version
8. **Creates archive** - (Optional) Generates a zip file for distribution

### Build Output

After successful build:

```
✅ n8n portable version built successfully!

📦 Build Output:
   Directory:      /path/to/n8n-atom-portable
   Size:           ~500MB (varies by platform)
   Archive:        n8n-atom-portable-2.2.0.zip

⏱️  Build Times:
   Copy Files:     15s
   Create Archive: 45s
   Total Time:     1m 0s

📋 Usage:
   Unix/Linux/macOS:  cd n8n-atom-portable && ./n8n start
   Windows:           cd n8n-atom-portable && n8n.cmd start
```

## Using Portable Mode

### System Requirements

- **Node.js**: Version 20.19 - 24.x installed on target system
- **Disk Space**: ~500MB for the portable directory
- **Permissions**: Execute permissions for Unix/Linux/macOS

### Quick Start

#### Unix/Linux/macOS

```bash
# Navigate to the portable directory
cd n8n-atom-portable

# Start n8n
./n8n start
```

#### Windows

```cmd
# Navigate to the portable directory
cd n8n-atom-portable

# Start n8n
n8n.cmd start
```

Or simply double-click `n8n.cmd` in Windows Explorer.

### Available Commands

The portable version supports all standard n8n commands:

```bash
# Start n8n server
./n8n start

# Start with tunnel (requires internet)
./n8n start --tunnel

# Start as worker
./n8n worker

# Start webhook server
./n8n webhook

# Show version
./n8n --version

# Display help
./n8n --help
```

### Configuration

#### Data Directory

By default, n8n stores data in:
- **Unix/Linux/macOS**: `~/.n8n`
- **Windows**: `%APPDATA%\n8n`

#### Environment Variables

Customize behavior using environment variables:

```bash
# Change port (default: 5678)
export N8N_PORT=5888
./n8n start

# Change host binding
export N8N_HOST=0.0.0.0
./n8n start

# Custom data directory
export N8N_USER_FOLDER=/path/to/custom/data
./n8n start

# Enable encryption for credentials
export N8N_ENCRYPTION_KEY="your-encryption-key"
./n8n start
```

On Windows:

```cmd
set N8N_PORT=5888
set N8N_HOST=0.0.0.0
n8n.cmd start
```

#### Configuration File

Create a `.env` file in the portable directory:

```bash
# .env file
N8N_PORT=5888
N8N_HOST=0.0.0.0
N8N_BASIC_AUTH_ACTIVE=true
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=password
```

## Distribution

### Creating Distribution Package

#### Option 1: Using Build Script

The build script automatically creates a zip archive:

```bash
pnpm build:portable
# Creates: n8n-atom-portable-2.2.0.zip
```

#### Option 2: Manual Archive Creation

If you disabled archive creation during build:

```bash
# Create tar.gz (Unix/Linux/macOS)
tar -czf n8n-atom-portable.tar.gz n8n-atom-portable/

# Create zip (cross-platform)
zip -r n8n-atom-portable.zip n8n-atom-portable/
```

### Sharing the Portable Version

1. **Via Network Share**
   ```bash
   # Copy to shared folder
   cp -r n8n-atom-portable /mnt/shared/
   ```

2. **Via USB Drive**
   ```bash
   # Copy to USB drive
   cp -r n8n-atom-portable /Volumes/USB_DRIVE/
   ```

3. **Via SCP/SFTP**
   ```bash
   # Upload to remote server
   scp n8n-atom-portable.zip user@server:/path/to/destination/
   ```

4. **Via Cloud Storage** (requires initial internet)
   - Upload zip to cloud storage
   - Recipients download and extract offline

## GitHub Release

### Publishing as GitHub Release

You can publish the portable version as a GitHub release to make it easily downloadable for users.

#### Prerequisites

1. **GitHub CLI** installed and authenticated:
   ```bash
   # Install GitHub CLI (if not installed)
   brew install gh  # macOS
   # Or visit: https://cli.github.com/

   # Authenticate
   gh auth login
   ```

2. **Repository access**: You need push/release permissions for the repository

3. **Portable archive built**: Run `pnpm build:portable` first

#### Quick Release

Create a release with default settings:

```bash
# Build portable version
pnpm build:portable

# Create GitHub release
pnpm release:portable
```

This will:
- Create a release tag like `portable-v2.2.0`
- Upload the portable zip file
- Generate release notes automatically
- Ask for confirmation before publishing

#### Release as Draft

Create a draft release for review:

```bash
pnpm release:portable:draft
```

Draft releases are not visible to the public and can be edited before publishing.

#### Release as Pre-release

Mark the release as pre-release (for beta/RC versions):

```bash
pnpm release:portable:prerelease
```

#### Custom Release Configuration

Customize the release using environment variables:

```bash
# Custom release tag
RELEASE_TAG=v2.2.0-portable pnpm release:portable

# Custom release title
RELEASE_TITLE="n8n Atom Portable Edition v2.2.0" pnpm release:portable

# Skip confirmation prompt (useful for CI/CD)
SKIP_CONFIRM=true pnpm release:portable

# Target specific branch or commit
TARGET_COMMITISH=main pnpm release:portable

# Combine options
DRAFT_RELEASE=true RELEASE_TAG=v2.2.0-beta PRERELEASE=true pnpm release:portable
```

#### Available Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `RELEASE_TAG` | Git tag for the release | `portable-v{version}` |
| `RELEASE_TITLE` | Release title | `n8n Portable v{version}` |
| `DRAFT_RELEASE` | Create as draft | `false` |
| `PRERELEASE` | Mark as pre-release | `false` |
| `SKIP_CONFIRM` | Skip confirmation prompt | `false` |
| `TARGET_COMMITISH` | Target branch/commit | (current branch) |
| `RELEASE_NOTES` | Custom release notes | (auto-generated) |

#### Manual Release (Using GitHub CLI)

If you prefer manual control:

```bash
# Create release with file upload
gh release create portable-v2.2.0 \
  n8n-atom-portable-2.2.0.zip \
  --title "n8n Portable v2.2.0" \
  --notes "See PORTABLE.md for usage instructions"

# Create draft release
gh release create portable-v2.2.0 \
  n8n-atom-portable-2.2.0.zip \
  --draft \
  --title "n8n Portable v2.2.0" \
  --notes-file release-notes.md

# View releases
gh release list

# View specific release
gh release view portable-v2.2.0

# Edit release
gh release edit portable-v2.2.0 --draft=false

# Delete release
gh release delete portable-v2.2.0
```

#### CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
name: Release Portable Version

on:
  push:
    tags:
      - 'v*'

jobs:
  release-portable:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Setup pnpm
        uses: pnpm/action-setup@v2
        with:
          version: 10.22.0

      - name: Install dependencies
        run: pnpm install

      - name: Build portable version
        run: pnpm build:portable

      - name: Create GitHub Release
        env:
          SKIP_CONFIRM: true
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: pnpm release:portable
```

#### Troubleshooting Release Issues

##### Issue: Tag already exists

```bash
# Check existing releases
gh release list

# Delete existing release and tag
gh release delete portable-v2.2.0 --yes
git tag -d portable-v2.2.0
git push origin :refs/tags/portable-v2.2.0

# Try again
pnpm release:portable
```

##### Issue: Authentication failed

```bash
# Check authentication status
gh auth status

# Re-authenticate
gh auth logout
gh auth login
```

##### Issue: Permission denied

```bash
# Verify repository permissions
gh repo view

# You need at least "Write" access to create releases
# Contact repository owner to grant permissions
```

##### Issue: Archive not found

```bash
# Build portable version first
pnpm build:portable

# Verify archive exists
ls -lh n8n-atom-portable-*.zip

# Then create release
pnpm release:portable
```

### Downloading Released Version

Users can download the portable version from GitHub:

```bash
# Download latest portable release
gh release download --pattern 'n8n-atom-portable-*.zip'

# Download specific version
gh release download portable-v2.2.0 --pattern 'n8n-atom-portable-*.zip'

# Or use curl
curl -L -O https://github.com/borgius/n8n-atom/releases/download/portable-v2.2.0/n8n-atom-portable-2.2.0.zip

# Extract and run
unzip n8n-atom-portable-2.2.0.zip
cd n8n-atom-portable
./n8n start
```

## Advanced Usage

### Running Multiple Instances

You can run multiple portable instances simultaneously by changing ports:

```bash
# Instance 1
cd n8n-atom-portable-1
export N8N_PORT=5678
./n8n start &

# Instance 2
cd n8n-atom-portable-2
export N8N_PORT=5679
./n8n start &
```

### Running as Background Service

#### Unix/Linux with systemd

Create a systemd service file:

```ini
# /etc/systemd/system/n8n-portable.service
[Unit]
Description=n8n Portable Workflow Automation
After=network.target

[Service]
Type=simple
User=n8n-user
WorkingDirectory=/opt/n8n-atom-portable
ExecStart=/opt/n8n-atom-portable/n8n start
Restart=on-failure
Environment=N8N_PORT=5678
Environment=N8N_HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable n8n-portable
sudo systemctl start n8n-portable
sudo systemctl status n8n-portable
```

#### macOS with launchd

Create a launch agent:

```xml
<!-- ~/Library/LaunchAgents/com.n8n.portable.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.n8n.portable</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/n8n-atom-portable/n8n</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/path/to/n8n-atom-portable</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>N8N_PORT</key>
        <string>5678</string>
    </dict>
</dict>
</plist>
```

Load and start:

```bash
launchctl load ~/Library/LaunchAgents/com.n8n.portable.plist
launchctl start com.n8n.portable
```

### Custom Startup Script

Create a wrapper script for additional setup:

```bash
#!/bin/bash
# start-n8n-custom.sh

# Set environment variables
export N8N_PORT=5888
export N8N_HOST=0.0.0.0
export N8N_ENCRYPTION_KEY="my-secure-key"
export N8N_USER_FOLDER="$HOME/.n8n-portable"

# Set Node.js options
export NODE_OPTIONS="--max-old-space-size=4096"

# Navigate to portable directory
cd "$(dirname "$0")"

# Start n8n
./n8n start
```

Make it executable and run:

```bash
chmod +x start-n8n-custom.sh
./start-n8n-custom.sh
```

## Troubleshooting

### Common Issues

#### Issue: Permission Denied (Unix/Linux/macOS)

**Symptom:**
```
-bash: ./n8n: Permission denied
```

**Solution:**
```bash
chmod +x n8n
./n8n start
```

#### Issue: Node.js Version Error

**Symptom:**
```
Your Node.js version X.X.X is currently not supported by n8n.
Please use a Node.js version that satisfies: >=20.19 <= 24.x
```

**Solution:**
```bash
# Check current version
node --version

# Install compatible Node.js version using nvm
nvm install 22
nvm use 22

# Or download from nodejs.org
```

#### Issue: Port Already in Use

**Symptom:**
```
Error: listen EADDRINUSE: address already in use :::5678
```

**Solution:**
```bash
# Option 1: Change port
export N8N_PORT=5888
./n8n start

# Option 2: Stop conflicting process
# Find process using port
lsof -ti :5678
# Kill it
kill -9 $(lsof -ti :5678)
```

#### Issue: Module Not Found

**Symptom:**
```
Error: Cannot find module 'some-package'
```

**Solution:**
```bash
# Verify node_modules directory exists
ls -la node_modules/

# If missing, rebuild from source:
cd /path/to/n8n-atom
pnpm build:portable
```

#### Issue: Startup Script Not Found (Windows)

**Symptom:**
```
'n8n.cmd' is not recognized as an internal or external command
```

**Solution:**
```cmd
# Make sure you're in the portable directory
cd path\to\n8n-atom-portable

# Use full path
path\to\n8n-atom-portable\n8n.cmd start
```

### Performance Tuning

#### Increase Memory Limit

For workflows with large datasets:

```bash
# Unix/Linux/macOS
export NODE_OPTIONS="--max-old-space-size=4096"
./n8n start

# Windows
set NODE_OPTIONS=--max-old-space-size=4096
n8n.cmd start
```

#### Enable Debug Logging

For troubleshooting:

```bash
# Set log level
export N8N_LOG_LEVEL=debug
./n8n start
```

### Verification

Check if n8n is running correctly:

```bash
# Check if port is listening
netstat -an | grep 5678

# Test HTTP endpoint
curl http://localhost:5678/healthz
# Expected: {"status":"ok"}

# Open in browser
open http://localhost:5678
# Or visit manually
```

## Technical Details

### How Portable Startup Works

The startup scripts override Node.js module resolution to ensure all dependencies load from the portable directory:

```javascript
// From the startup script
const scriptDir = path.dirname(__filename);
const portableDir = path.resolve(scriptDir);

// Set NODE_PATH to local node_modules
const nodeModulesPath = path.join(portableDir, 'node_modules');
process.env.NODE_PATH = nodeModulesPath;

// Override module resolution
Module._resolveFilename = function(request, parent, isMain, options) {
    if (request === 'n8n/package.json') {
        return path.join(portableDir, 'package.json');
    }
    return originalResolve.call(this, request, parent, isMain, options);
};

// Set config directory
process.env.NODE_CONFIG_DIR = path.join(portableDir, 'config');
```

### Differences from Regular Installation

| Feature | Regular Installation | Portable Mode |
|---------|---------------------|---------------|
| Dependencies | Installed in global/local node_modules | Bundled in package |
| Internet Required | Yes (for npm install) | No |
| Build Tools | pnpm/npm required | Not required |
| Distribution | Requires setup | Copy & run |
| Updates | `pnpm install` | Replace entire directory |
| Size | ~200MB (without node_modules) | ~500MB (with all deps) |
| Startup Speed | Fast | Fast (same) |

### Environment Variables Reference

Key environment variables for portable mode:

| Variable | Description | Default |
|----------|-------------|---------|
| `N8N_PORT` | HTTP port for n8n | `5678` |
| `N8N_HOST` | Host to bind to | `localhost` |
| `N8N_USER_FOLDER` | Data directory | `~/.n8n` |
| `N8N_ENCRYPTION_KEY` | Credential encryption key | (none) |
| `N8N_BASIC_AUTH_ACTIVE` | Enable basic auth | `false` |
| `N8N_BASIC_AUTH_USER` | Basic auth username | (none) |
| `N8N_BASIC_AUTH_PASSWORD` | Basic auth password | (none) |
| `NODE_CONFIG_DIR` | Config directory | `{portable}/config` |
| `NODE_PATH` | Node module path | `{portable}/node_modules` |
| `NODE_OPTIONS` | Node.js runtime options | (none) |

For a complete list of environment variables, see the [n8n documentation](https://docs.n8n.io/hosting/configuration/environment-variables/).

## Security Considerations

### Protecting Credentials

1. **Always set an encryption key**:
   ```bash
   export N8N_ENCRYPTION_KEY="$(openssl rand -hex 32)"
   ./n8n start
   ```

2. **Save the key securely** - If you lose it, credentials cannot be decrypted

3. **Use basic authentication** for web access:
   ```bash
   export N8N_BASIC_AUTH_ACTIVE=true
   export N8N_BASIC_AUTH_USER=admin
   export N8N_BASIC_AUTH_PASSWORD="$(openssl rand -base64 32)"
   ./n8n start
   ```

### File Permissions

Secure the portable directory:

```bash
# Restrict directory access
chmod 750 n8n-atom-portable

# Protect sensitive files
chmod 600 n8n-atom-portable/.env
```

### Network Security

For production deployments:

```bash
# Bind to localhost only (access via reverse proxy)
export N8N_HOST=127.0.0.1

# Or use firewall rules
# Allow only specific IPs to access port 5678
```

## Updating Portable Version

To update to a new version:

1. Build new portable version from updated source
2. Stop running n8n instance
3. Backup your data directory (`~/.n8n`)
4. Replace old portable directory with new one
5. Start n8n with new version

```bash
# Backup data
cp -r ~/.n8n ~/.n8n.backup

# Stop old instance
pkill -f "n8n start"

# Replace with new version
rm -rf n8n-atom-portable-old
mv n8n-atom-portable n8n-atom-portable-old
unzip n8n-atom-portable-2.3.0.zip

# Start new version
cd n8n-atom-portable
./n8n start
```

## Examples

### Example 1: USB Drive Deployment

```bash
# On build machine
cd /path/to/n8n-atom
pnpm build:portable

# Copy to USB
cp n8n-atom-portable.zip /Volumes/USB_DRIVE/

# On target machine (no internet)
cd /Volumes/USB_DRIVE
unzip n8n-atom-portable.zip
cd n8n-atom-portable
./n8n start
```

### Example 2: Air-Gapped Server

```bash
# Build on internet-connected machine
pnpm build:portable

# Transfer via SCP
scp n8n-atom-portable.zip admin@airgapped-server:/opt/

# On air-gapped server
ssh admin@airgapped-server
cd /opt
unzip n8n-atom-portable.zip
cd n8n-atom-portable

# Configure for production
export N8N_PORT=5678
export N8N_HOST=0.0.0.0
export N8N_ENCRYPTION_KEY="your-secure-key"

# Start as service
./n8n start
```

### Example 3: Multiple Team Members

```bash
# Create portable version
pnpm build:portable

# Share via network
cp -r n8n-atom-portable /mnt/shared-drive/tools/

# Each team member:
cp -r /mnt/shared-drive/tools/n8n-atom-portable ~/tools/
cd ~/tools/n8n-atom-portable

# Run with custom port to avoid conflicts
export N8N_PORT=$((5678 + $RANDOM % 1000))
./n8n start
```

## FAQ

### Q: Can I use portable mode for production?

**A:** Yes, but consider:
- Use proper security (encryption keys, basic auth)
- Set up monitoring and logging
- Use a process manager (systemd, PM2)
- Configure backups for data directory
- Use a reverse proxy (nginx, Apache) for SSL

### Q: How do I update community nodes in portable mode?

**A:** Community nodes need internet access to install. Options:
1. Connect temporarily to internet and use n8n UI to install
2. Install nodes on a connected machine, rebuild portable version
3. Manually copy node packages to portable's node_modules

### Q: Does portable mode support all n8n features?

**A:** Yes, portable mode is fully featured. The only limitation is that features requiring internet (webhooks from external services, tunnel mode, community node installation) need connectivity.

### Q: How large is a typical portable build?

**A:** Approximately 400-600MB depending on platform and optional dependencies.

### Q: Can I create a portable version for a different platform?

**A:** The build must be done on the target platform (or use Docker cross-compilation), as some native modules are platform-specific.

## Support and Resources

- **Official Documentation**: https://docs.n8n.io
- **Community Forum**: https://community.n8n.io
- **GitHub Issues**: https://github.com/n8n-io/n8n/issues
- **n8n-atom Repository**: https://github.com/borgius/n8n-atom
- **Upstream Fork**: https://github.com/KhanhPham2411/n8n-atom

## Contributing

If you find issues with portable mode or have suggestions for improvements, please:

1. Check existing issues in the repository
2. Create a new issue with detailed information
3. Submit a pull request with fixes or enhancements

## License

The portable version follows the same license as n8n. See [LICENSE.md](LICENSE.md) and [LICENSE_EE.md](LICENSE_EE.md) for details.
