# GitHub Actions Workflows

## Semantic Release Workflow

The `semantic.yml` workflow automatically creates version tags and GitHub releases based on conventional commits.

### How it works

1. **Triggers on**:
   - Push to `main` branch
   - Manual workflow dispatch

2. **What it does**:
   - Analyzes commit messages following [Conventional Commits](https://www.conventionalcommits.org/)
   - Determines the next version number (major.minor.patch)
   - Creates a git tag with the new version
   - Generates release notes from commit messages
   - Creates a GitHub release
   - Updates CHANGELOG.md

3. **Version bumping rules**:
   - `feat:` commits trigger a minor version bump (e.g., 1.0.0 → 1.1.0)
   - `fix:` commits trigger a patch version bump (e.g., 1.0.0 → 1.0.1)
   - `BREAKING CHANGE:` in commit body triggers a major version bump (e.g., 1.0.0 → 2.0.0)
   - Other commit types (`docs:`, `style:`, `refactor:`, `test:`, `chore:`) don't trigger releases

### Commit message examples

```bash
# Minor version bump (new feature)
git commit -m "feat: add support for RSA-PSS signatures"

# Patch version bump (bug fix)
git commit -m "fix: correct key validation logic"

# Major version bump (breaking change)
git commit -m "feat!: change API signature for GenerateKeyPair

BREAKING CHANGE: The GenerateKeyPair function now requires an additional parameter"

# No version bump (documentation)
git commit -m "docs: update installation instructions"
```

### Local testing

To test semantic-release locally:

```bash
# Install dependencies
npm install

# Dry run (shows what would happen without making changes)
npm run release:dry
```

### Manual trigger

You can manually trigger the workflow from GitHub Actions tab:
1. Go to Actions tab
2. Select "Semantic Release" workflow
3. Click "Run workflow"
4. Select branch and run

### Configuration

- `.releaserc.json` - Semantic release configuration
- `package.json` - Node dependencies for semantic-release

### Requirements

- Commits must follow Conventional Commits format
- The workflow needs write permissions for contents, issues, and pull requests
- Uses the built-in `GITHUB_TOKEN` for authentication