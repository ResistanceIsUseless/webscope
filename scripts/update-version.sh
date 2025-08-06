#!/bin/bash

# WebScope Version Update Script
# Usage: ./scripts/update-version.sh [major|minor|patch] [new-version]
# Example: ./scripts/update-version.sh minor 1.1.0

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 [major|minor|patch] [new-version]"
    echo "Example: $0 minor 1.1.0"
    echo "Example: $0 patch (auto-increment)"
    exit 1
fi

TYPE=$1
NEW_VERSION=$2

# Get current version
CURRENT_VERSION=$(cat VERSION)
echo "Current version: $CURRENT_VERSION"

# Auto-increment version if not provided
if [ -z "$NEW_VERSION" ]; then
    IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
    MAJOR=${VERSION_PARTS[0]}
    MINOR=${VERSION_PARTS[1]}
    PATCH=${VERSION_PARTS[2]}
    
    case $TYPE in
        major)
            MAJOR=$((MAJOR + 1))
            MINOR=0
            PATCH=0
            ;;
        minor)
            MINOR=$((MINOR + 1))
            PATCH=0
            ;;
        patch)
            PATCH=$((PATCH + 1))
            ;;
        *)
            echo "Invalid type: $TYPE (must be major, minor, or patch)"
            exit 1
            ;;
    esac
    
    NEW_VERSION="$MAJOR.$MINOR.$PATCH"
fi

echo "New version: $NEW_VERSION"

# Validate version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version format: $NEW_VERSION (must be X.Y.Z)"
    exit 1
fi

# Update VERSION file
echo "$NEW_VERSION" > VERSION

# Update main.go
sed -i.bak "s/appVersion = \"$CURRENT_VERSION\"/appVersion = \"$NEW_VERSION\"/" main.go
rm main.go.bak

# Update README.md badge
sed -i.bak "s/version-$CURRENT_VERSION-blue/version-$NEW_VERSION-blue/" README.md
rm README.md.bak

# Update CLAUDE.md if it exists
if [ -f "CLAUDE.md" ]; then
    sed -i.bak "s/webscope version $CURRENT_VERSION/webscope version $NEW_VERSION/g" CLAUDE.md
    rm CLAUDE.md.bak 2>/dev/null || true
fi

echo ""
echo "Version updated from $CURRENT_VERSION to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "1. Update CHANGELOG.md with release notes"
echo "2. Test the build: go build"
echo "3. Commit changes: git add . && git commit -m 'Release version $NEW_VERSION'"
echo "4. Create git tag: git tag -a v$NEW_VERSION -m 'Release version $NEW_VERSION'"
echo "5. Push changes: git push origin main && git push origin v$NEW_VERSION"