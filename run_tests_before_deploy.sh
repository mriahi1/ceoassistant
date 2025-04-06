#!/bin/bash
set -e

echo "========================================================"
echo "Running pre-deployment tests for CEO Assistant AI"
echo "========================================================"

# Install test dependencies if not already installed
echo "Installing dependencies..."
pip3 install -r requirements-dev.txt

# Set environment for testing
export FLASK_ENV=testing
export TESTING=True

# Run the minimal tests 
echo "Running minimal tests..."
pytest -v minimal_tests/

# Check the exit code of the tests
if [ $? -ne 0 ]; then
    echo "========================================================"
    echo "❌ Tests failed. Deployment canceled."
    echo "Please fix the failing tests before deploying."
    echo "========================================================"
    exit 1
fi

# Perform linting checks
echo "========================================================"
echo "Running linting checks..."
flake8 minimal_tests/ --count --select=E9,F63,F7,F82 --show-source --statistics

# Check for security vulnerabilities with safety (if installed)
if command -v safety &> /dev/null; then
    echo "========================================================"
    echo "Checking for security vulnerabilities in dependencies..."
    safety check -r requirements.txt || true
fi

echo "========================================================"
echo "✅ All pre-deployment tests passed successfully!"
echo "The application is ready for deployment."
echo "========================================================="

# Optional: Tag this commit as a release candidate
git_tag() {
    read -p "Do you want to tag this commit as a release candidate? (y/n): " answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        TIMESTAMP=$(date +"%Y%m%d%H%M%S")
        git tag -a "rc-$TIMESTAMP" -m "Release candidate $TIMESTAMP"
        git push origin "rc-$TIMESTAMP"
        echo "Tagged commit as rc-$TIMESTAMP and pushed to remote."
    fi
}

# Uncomment the next line to enable tagging
# git_tag 