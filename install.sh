#!/bin/bash
# auto-update-reqs.sh - A script to install the auto-requirements updater

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/auto-update-reqs

# Create the main Python script
cat > ~/.local/bin/update_requirements.py << 'EOF'
#!/usr/bin/env python3
"""
Auto Requirements Updater
Scans for Python projects and updates their requirements with modern equivalents.
"""
import os
import re
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime

# Configure logging
LOG_FILE = os.path.expanduser("~/.config/auto-update-reqs/update_log.txt")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Package replacements mapping
PACKAGE_REPLACEMENTS = {
    'pyaes': 'pycryptodome',
    'pycrypto': 'pycryptodome',
    'flask-script': 'flask>=2.0.0',
    'django-smartpages': 'django-flatpages',
    'python-memcached': 'pymemcache',
    'mock': 'pytest-mock',
    'nose': 'pytest',
    'unittest2': 'pytest',
    # Add more replacements as needed
}

def find_python_projects(start_dir=None):
    """Find all Python projects starting from start_dir."""
    if start_dir is None:
        start_dir = os.path.expanduser("~")
    
    python_projects = []
    
    # Files that indicate a Python project
    project_markers = [
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "Pipfile",
        "poetry.lock"
    ]
    
    # Directories to exclude
    exclude_dirs = [
        ".git", ".svn", ".hg",
        "node_modules", "venv", "env",
        ".venv", ".env", "__pycache__",
        ".pytest_cache", ".tox", 
        "build", "dist", ".eggs"
    ]
    
    logging.info(f"Scanning for Python projects in {start_dir}")
    
    for root, dirs, files in os.walk(start_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        # Check if this is a Python project
        for marker in project_markers:
            if marker in files:
                python_projects.append(root)
                logging.info(f"Found Python project: {root}")
                break
    
    return python_projects

def update_requirements_file(requirements_file):
    """Update a requirements.txt file with modern equivalents."""
    if not os.path.exists(requirements_file):
        return False
    
    logging.info(f"Updating {requirements_file}")
    
    # Read the requirements file
    with open(requirements_file, 'r') as f:
        requirements = f.read()
    
    # Make a backup
    backup_file = f"{requirements_file}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    with open(backup_file, 'w') as f:
        f.write(requirements)
    
    # Update requirements
    updated = False
    for old_pkg, new_pkg in PACKAGE_REPLACEMENTS.items():
        # Match package name at start of line, optionally followed by version constraints
        pattern = rf"^{re.escape(old_pkg)}(==|>=|<=|~=|!=|>|<|@|$|[^\w\.-])"
        if re.search(pattern, requirements, re.MULTILINE):
            requirements = re.sub(pattern, f"{new_pkg}\\1", requirements, flags=re.MULTILINE)
            logging.info(f"  Replaced {old_pkg} with {new_pkg}")
            updated = True
    
    if updated:
        with open(requirements_file, 'w') as f:
            f.write(requirements)
        logging.info(f"  Updated {requirements_file}")
        return True
    else:
        logging.info(f"  No updates needed for {requirements_file}")
        return False

def process_python_project(project_dir):
    """Process a Python project directory for requirements updates."""
    logging.info(f"Processing project: {project_dir}")
    
    # Check for requirements.txt
    requirements_file = os.path.join(project_dir, "requirements.txt")
    if os.path.exists(requirements_file):
        update_requirements_file(requirements_file)
    
    # Check for dev-requirements.txt
    dev_requirements_file = os.path.join(project_dir, "dev-requirements.txt")
    if os.path.exists(dev_requirements_file):
        update_requirements_file(dev_requirements_file)
    
    # Check for requirements in a requirements directory
    req_dir = os.path.join(project_dir, "requirements")
    if os.path.exists(req_dir) and os.path.isdir(req_dir):
        for file in os.listdir(req_dir):
            if file.endswith(".txt"):
                update_requirements_file(os.path.join(req_dir, file))

def main():
    """Main function to find and update Python projects."""
    logging.info("Starting auto-requirements updater")
    
    # Load config or create default
    config_file = os.path.expanduser("~/.config/auto-update-reqs/config.json")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "scan_directories": [os.path.expanduser("~")],
            "exclude_directories": [],
            "package_replacements": PACKAGE_REPLACEMENTS
        }
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    projects_updated = 0
    
    # Process each scan directory
    for scan_dir in config["scan_directories"]:
        scan_dir = os.path.expanduser(scan_dir)
        if not os.path.exists(scan_dir):
            logging.warning(f"Scan directory does not exist: {scan_dir}")
            continue
        
        python_projects = find_python_projects(scan_dir)
        logging.info(f"Found {len(python_projects)} Python projects in {scan_dir}")
        
        for project in python_projects:
            # Skip excluded directories
            if any(project.startswith(os.path.expanduser(exclude)) for exclude in config["exclude_directories"]):
                logging.info(f"Skipping excluded project: {project}")
                continue
            
            process_python_project(project)
            projects_updated += 1
    
    logging.info(f"Completed processing {projects_updated} Python projects")

if __name__ == "__main__":
    main()
EOF

# Make the script executable
chmod +x ~/.local/bin/update_requirements.py

# Create the systemd service file
cat > ~/.config/systemd/user/auto-update-reqs.service << 'EOF'
[Unit]
Description=Auto Update Python Requirements
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "~/.local/bin/update_requirements.py"
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

# Create the timer unit to run at boot and periodically
cat > ~/.config/systemd/user/auto-update-reqs.timer << 'EOF'
[Unit]
Description=Run Auto Update Python Requirements Weekly

[Timer]
OnBootSec=2min
OnUnitActiveSec=1week
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Create initial config file
mkdir -p ~/.config/auto-update-reqs
cat > ~/.config/auto-update-reqs/config.json << 'EOF'
{
  "scan_directories": ["~/"],
  "exclude_directories": ["~/anaconda3", "~/miniconda3", "~/venv", "~/.venv"],
  "package_replacements": {
    "pyaes": "pycryptodome",
    "pycrypto": "pycryptodome",
    "flask-script": "flask>=2.0.0",
    "django-smartpages": "django-flatpages",
    "python-memcached": "pymemcache",
    "mock": "pytest-mock",
    "nose": "pytest",
    "unittest2": "pytest"
  }
}
EOF

# Enable and start the timer
systemctl --user enable auto-update-reqs.timer
systemctl --user start auto-update-reqs.timer

echo "Auto-requirements updater has been installed!"
echo "The script will run on boot and weekly thereafter"
echo "Configuration file: ~/.config/auto-update-reqs/config.json"
echo "Logs: ~/.config/auto-update-reqs/update_log.txt"
echo "To run manually: ~/.local/bin/update_requirements.py"
