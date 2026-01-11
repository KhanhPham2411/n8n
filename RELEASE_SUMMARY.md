# ✅ GitHub Release Setup Complete

## Summary

Successfully set up automated GitHub release creation for n8n-atom portable version!

### What Was Created

1. **Release Script**: [scripts/release-portable.mjs](scripts/release-portable.mjs)
   - Automated GitHub release creation
   - Archive upload
   - Auto-generated release notes
   - Error handling and validation

2. **Package Commands**: Added to [package.json](package.json)
   - `pnpm release:portable` - Create public release
   - `pnpm release:portable:draft` - Create draft release
   - `pnpm release:portable:prerelease` - Create pre-release

3. **Documentation**: Updated [PORTABLE.md](PORTABLE.md)
   - Complete GitHub Release section
   - Usage examples
   - CI/CD integration guide
   - Troubleshooting

4. **Quick Reference**: [RELEASE_PORTABLE_QUICK_REF.md](RELEASE_PORTABLE_QUICK_REF.md)
   - Quick command reference
   - Environment variables
   - Manual commands

### Test Release Created ✅

**Draft release successfully created:**
- Repository: **borgius/n8n-atom**
- Tag: `portable-v2.2.0`
- Status: **Draft** (not publicly visible yet)
- Archive: `n8n-atom-portable-2.2.0.zip` (240M)
- URL: https://github.com/borgius/n8n-atom/releases/tag/portable-v2.2.0

### Repository Configuration

```
origin   → https://github.com/borgius/n8n-atom.git (YOUR FORK)
upstream → https://github.com/KhanhPham2411/n8n-atom.git (UPSTREAM)
n8n      → https://github.com/n8n-io/n8n.git (ORIGINAL)
```

The release script automatically detects the `origin` remote and publishes to **borgius/n8n-atom**.

## Quick Usage

### Create a Release (With Confirmation)

```bash
# Build portable version
pnpm build:portable

# Create release (will ask for confirmation)
pnpm release:portable
```

### Create Draft Release (No Confirmation)

```bash
# Build and create draft
pnpm build:portable
SKIP_CONFIRM=true DRAFT_RELEASE=true pnpm release:portable
```

### Publish the Draft Release

```bash
# Option 1: Edit via GitHub web interface
# Visit: https://github.com/borgius/n8n-atom/releases
# Click "Edit" on the draft, then "Publish release"

# Option 2: Publish via CLI
gh release edit portable-v2.2.0 --draft=false

# Option 3: Delete draft and create public release
gh release delete portable-v2.2.0 --yes
pnpm release:portable
```

### Create Pre-release

```bash
pnpm build:portable
pnpm release:portable:prerelease
```

## Available Commands

| Command | Description | Visibility |
|---------|-------------|------------|
| `pnpm release:portable` | Create public release | Public |
| `pnpm release:portable:draft` | Create draft release | Private |
| `pnpm release:portable:prerelease` | Create pre-release | Public (marked as pre-release) |

## Environment Variables

```bash
# Custom release tag
RELEASE_TAG=v2.2.0-portable pnpm release:portable

# Custom release title
RELEASE_TITLE="Custom Title" pnpm release:portable

# Skip confirmation prompt
SKIP_CONFIRM=true pnpm release:portable

# Target specific branch/commit
TARGET_COMMITISH=main pnpm release:portable

# Custom release notes (multiline)
RELEASE_NOTES="My custom notes" pnpm release:portable

# Combine multiple options
DRAFT_RELEASE=true SKIP_CONFIRM=true RELEASE_TAG=v2.2.0-beta pnpm release:portable
```

## Manual GitHub CLI Commands

```bash
# View releases
gh release list

# View specific release
gh release view portable-v2.2.0

# Download release
gh release download portable-v2.2.0

# Edit release (change draft to public)
gh release edit portable-v2.2.0 --draft=false

# Delete release
gh release delete portable-v2.2.0 --yes

# Create release manually
gh release create portable-v2.2.0 \
  n8n-atom-portable-2.2.0.zip \
  --title "n8n Portable v2.2.0" \
  --notes "Portable version with all dependencies" \
  --draft
```

## Next Steps

### 1. Review the Draft Release

Visit: https://github.com/borgius/n8n-atom/releases

The draft release is currently visible only to you. Review:
- Release notes
- Attached archive
- Tag name
- Target branch

### 2. Publish the Release

When ready to make it public:

```bash
# Option A: Via GitHub web interface
# 1. Go to https://github.com/borgius/n8n-atom/releases
# 2. Click "Edit" on the draft
# 3. Click "Publish release"

# Option B: Via CLI
gh release edit portable-v2.2.0 --draft=false
```

### 3. Test Download

After publishing:

```bash
# Download and test
gh release download portable-v2.2.0
unzip n8n-atom-portable-2.2.0.zip
cd n8n-atom-portable
./n8n start
```

### 4. Update Documentation

If needed, update:
- README.md with download links
- CHANGELOG.md with version notes
- Any installation guides

## Typical Release Workflow

```bash
# 1. Update version in package.json if needed
# vim package.json

# 2. Commit changes
git add .
git commit -m "Prepare release v2.2.0"
git push origin local

# 3. Build portable version
pnpm build:portable

# 4. Create draft release for review
DRAFT_RELEASE=true pnpm release:portable

# 5. Review at https://github.com/borgius/n8n-atom/releases

# 6. Publish when ready
gh release edit portable-v2.2.0 --draft=false

# 7. Announce the release!
```

## Troubleshooting

### Issue: "workflow scope may be required"

Already fixed! The auth was refreshed with workflow scope.

If it happens again:
```bash
gh auth refresh -h github.com -s workflow
```

### Issue: Tag already exists

```bash
# Delete existing release and tag
gh release delete portable-v2.2.0 --yes
git tag -d portable-v2.2.0
git push origin :refs/tags/portable-v2.2.0

# Create new release
pnpm release:portable
```

### Issue: Wrong repository

The script now automatically detects `origin` remote:
```bash
# Verify origin
git remote get-url origin
# Should show: https://github.com/borgius/n8n-atom.git

# Set gh CLI default
gh repo set-default borgius/n8n-atom
```

### Issue: Archive not found

```bash
# Build first
pnpm build:portable

# Verify archive exists
ls -lh n8n-atom-portable-*.zip

# Then release
pnpm release:portable
```

## CI/CD Integration Example

Create `.github/workflows/release-portable.yml`:

```yaml
name: Release Portable Version

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  release-portable:
    runs-on: ubuntu-latest
    permissions:
      contents: write

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
        run: pnpm install --frozen-lockfile

      - name: Build portable version
        run: pnpm build:portable

      - name: Create GitHub Release
        env:
          SKIP_CONFIRM: true
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: pnpm release:portable
```

## Files Created/Modified

### Created
- ✅ `scripts/release-portable.mjs` - Release automation script
- ✅ `RELEASE_PORTABLE_QUICK_REF.md` - Quick reference guide
- ✅ `RELEASE_SUMMARY.md` - This summary document

### Modified
- ✅ `package.json` - Added release commands
- ✅ `PORTABLE.md` - Added GitHub Release section

### Test Artifacts
- ✅ Draft release created at: https://github.com/borgius/n8n-atom/releases/tag/portable-v2.2.0

## Support

For issues or questions:
- **Repository**: https://github.com/borgius/n8n-atom
- **Upstream**: https://github.com/KhanhPham2411/n8n-atom
- **n8n Docs**: https://docs.n8n.io

---

**Status**: ✅ Ready to use! The draft release has been created successfully.
**Action Required**: Review and publish the draft release when ready.
