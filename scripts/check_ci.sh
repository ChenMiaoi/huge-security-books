#!/usr/bin/env bash

# Enable strict error checking:
# -e: exit immediately if a command exits with a non-zero status
# -u: treat unset variables as an error
# -o pipefail: pipeline fails if any command in it fails
set -euo pipefail

# Function: Check if a command exists
# Usage: check_command <command_name>
check_command() {
    local cmd="$1"
    local pkg="$1"

    if command -v "$cmd" &> /dev/null; then
        echo "✅ Command '$cmd' is already installed."
        return 0
    fi

    echo "❌ Command '$cmd' not found. Attempting to install..."

    if command -v apt &> /dev/null; then
        # Debian / Ubuntu 系
        echo "🔧 Detected apt. Trying to install '$pkg'..."
        sudo apt update && sudo apt install -y "$pkg"
    elif command -v dnf &> /dev/null; then
        # Fedora / RHEL 8+
        echo "🔧 Detected dnf. Trying to install '$pkg'..."
        sudo dnf install -y "$pkg"
    elif command -v yum &> /dev/null; then
        # CentOS / RHEL 7 及以下
        echo "🔧 Detected yum. Trying to install '$pkg'..."
        sudo yum install -y "$pkg"
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        echo "🔧 Detected pacman. Trying to install '$pkg'..."
        sudo pacman -Sy --noconfirm "$pkg"
    elif command -v zypper &> /dev/null; then
        # openSUSE
        echo "🔧 Detected zypper. Trying to install '$pkg'..."
        sudo zypper install -y "$pkg"
    elif command -v brew &> /dev/null; then
        # macOS (Homebrew)
        echo "🔧 Detected Homebrew. Trying to install '$pkg'..."
        brew install "$pkg"
    else
        echo "❌ Error: Command '$cmd' is not installed, and no supported package manager was found."
        echo "   Please install '$cmd' manually."
        echo "   Common package names for '$cmd':"
        echo "     - Ubuntu/Debian: '$pkg' (apt)"
        echo "     - Fedora/RHEL: '$pkg' (dnf/yum)"
        echo "     - Arch: '$pkg' (pacman)"
        echo "     - macOS: try 'brew install $pkg'"
        exit 1
    fi

    if command -v "$cmd" &> /dev/null; then
        echo "✅ Successfully installed '$cmd'!"
    else
        echo "❌ Failed to install '$cmd'. Please install it manually."
        exit 1
    fi
}

# ================================
# Step 1: Check for required tools
# ================================
echo "✅ Checking for required command-line tools..."

# List of tools we depend on
check_command cargo     # Rust’s build system and package manager
check_command mdbook    # Tool for building books from Markdown (like MkDocs)
check_command aspell    # Spell checker
check_command shellcheck # Shell script static analyzer

echo "🔍 All required tools are installed: cargo, mdbook, aspell, shellcheck"
echo ""

# ========================================
# Step 2: Build the `trpl` package
# ========================================
echo "📦 Building the 'trpl' package (inside packages/trpl/)..."

pushd packages/trpl > /dev/null 2>&1 || {
    echo "❌ Error: Failed to enter directory 'packages/trpl'"
    exit 1
}

echo "🔨 Running 'cargo build' in packages/trpl/"
cargo build || {
    echo "❌ Error: 'cargo build' failed in packages/trpl/"
    popd > /dev/null 2>&1 || true
    exit 1
}

popd > /dev/null 2>&1 || {
    echo "❌ Error: Failed to return from packages/trpl/"
    exit 1
}

echo "✅ Successfully built 'trpl' package"
echo ""

# ========================================
# Step 3: Run tests for the main project
# ========================================
echo "🧪 Running main project tests with 'cargo test'..."

cargo test || {
    echo "❌ Error: 'cargo test' failed in the main project"
    exit 1
}

echo "✅ Main project tests passed"
echo ""

# ========================================
# Step 4: Run tests for the `mdbook-trpl` package
# ========================================
echo "📦 Building and testing the 'mdbook-trpl' package (inside packages/mdbook-trpl/)..."

pushd packages/mdbook-trpl > /dev/null 2>&1 || {
    echo "❌ Error: Failed to enter directory 'packages/mdbook-trpl'"
    exit 1
}

echo "🧪 Running 'cargo test' in packages/mdbook-trpl/"
cargo test || {
    echo "❌ Error: 'cargo test' failed in packages/mdbook-trpl/"
    popd > /dev/null 2>&1 || true
    exit 1
}

popd > /dev/null 2>&1 || {
    echo "❌ Error: Failed to return from packages/mdbook-trpl/"
    exit 1
}

echo "✅ Successfully tested 'mdbook-trpl' package"
echo ""

# ========================================
# Step 5: (Optional) Install mdbook-trpl globally
# ========================================
# Uncomment the following lines if you want to install your mdbook plugin/tool globally
#
# echo "🔧 Installing 'mdbook-trpl' to cargo's global bin directory..."
# cargo install --path packages/mdbook-trpl || {
#     echo "❌ Error: Failed to install mdbook-trpl via 'cargo install'"
#     exit 1
# }
#
# echo "✅ 'mdbook-trpl' installed successfully"
# echo ""

echo "🔤 Running spellcheck all scripts..."

exclude_dirs=(
    "*/packages/autocorrect/**"
    "*/src/fuzz/books/codes/.venv/**"
    "*/book/**"
)

find_args=()

for pattern in "${exclude_dirs[@]}"; do
    find_args+=(-not -path "$pattern")
done

find . -name "*.sh" -type f "${find_args[@]}" -exec shellcheck {} + || {
    echo "❌ Error: shellcheck failed"
    popd > /dev/null 2>&1 || true
    exit 1
}

echo "✅ Spellcheck script ran successfully"
echo ""

# ========================================
# Step 6: Run spellcheck script
# ========================================
echo "🔤 Running spellcheck script (ci/spellcheck.sh list)..."

bash ci/spellcheck.sh list || {
    echo "❌ Error: 'bash ci/spellcheck.sh list' failed"
    popd > /dev/null 2>&1 || true
    exit 1
}

echo "✅ Spellcheck script ran successfully"
echo ""

# ========================================
# Step 7: Build the mdBook documentation
# ========================================
echo "📖 Building mdBook documentation with 'mdbook build'..."

mdbook build || {
    echo "❌ Error: 'mdbook build' failed. Check your book configuration."
    exit 1
}

echo "✅ mdBook documentation built successfully"
echo ""

# ========================================
# Step 8: Run custom tool `lfp` (assumed to be a cargo binary)
# ========================================
echo "⚙️  Running custom tool: 'cargo run --bin lfp src'..."

cargo run --bin lfp src || {
    echo "❌ Error: Failed to run 'cargo run --bin lfp src'. Is the binary correctly built?"
    exit 1
}

echo "✅ Custom tool 'lfp' executed successfully"
echo ""

# ========================================
# Step 9: Run validation script (ci/validate.sh)
# ========================================
echo "✅ Running validation script: 'bash ci/validate.sh'..."

bash ci/validate.sh || {
    echo "❌ Error: 'bash ci/validate.sh' failed"
    popd > /dev/null 2>&1 || true
    exit 1
}

echo "✅ Validation script completed successfully"
echo ""

# ========================================
# Step 10: Run link checker script (scripts/linkcheck.sh)
# ========================================
echo "🔗 Running link checker: 'bash scripts/linkcheck.sh book'..."

bash scripts/linkcheck.sh -i book || {
    echo "❌ Error: 'bash scripts/linkcheck.sh book' failed. Check for broken links."
    popd > /dev/null 2>&1 || true
    exit 1
}

echo "✅ Link checking completed successfully"
echo ""

# ========================================
# All steps completed!
# ========================================
echo "🎉 All steps executed successfully. 🚀"
