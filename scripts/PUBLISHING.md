# Publishing Tweek

## Prerequisites

```bash
# Install build tools
pip install build twine

# Create PyPI account at https://pypi.org/account/register/
# Create API token at https://pypi.org/manage/account/token/
```

## Publish to PyPI

```bash
# 1. Update version in pyproject.toml
#    version = "0.1.0" → "0.2.0"

# 2. Build the package
python -m build

# 3. Check the build
twine check dist/*

# 4. Upload to Test PyPI first (optional but recommended)
twine upload --repository testpypi dist/*

# 5. Test install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ tweek

# 6. Upload to real PyPI
twine upload dist/*
```

## After Publishing

Users can install with:
```bash
pip install tweek
```

## Setting Up the Curl Installer

1. Host `scripts/install.sh` on GitHub (already done)
2. Optionally set up a short URL:
   - Point `get.tweek.dev` to the raw GitHub URL
   - Or use a URL shortener

Then users can run:
```bash
curl -sSL https://raw.githubusercontent.com/tweek-security/tweek/main/scripts/install.sh | bash
```

## Homebrew (Optional)

Create a Homebrew tap for macOS users:

1. Create repo `tweek-security/homebrew-tap`
2. Add formula `Formula/tweek.rb`:

```ruby
class Tweek < Formula
  include Language::Python::Virtualenv

  desc "Defense-in-depth security for AI coding assistants"
  homepage "https://tweek.dev"
  url "https://files.pythonhosted.org/packages/source/t/tweek/tweek-0.1.0.tar.gz"
  sha256 "HASH_HERE"
  license "MIT"

  depends_on "python@3.11"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/tweek", "--version"
  end
end
```

Then users can:
```bash
brew tap tweek-security/tap
brew install tweek
```

## Version Checklist

Before each release:
- [ ] Update version in `pyproject.toml`
- [ ] Update CHANGELOG.md (if exists)
- [ ] Run tests: `pytest`
- [ ] Build: `python -m build`
- [ ] Check: `twine check dist/*`
- [ ] Tag release: `git tag v0.x.0 && git push --tags`
- [ ] Upload: `twine upload dist/*`
