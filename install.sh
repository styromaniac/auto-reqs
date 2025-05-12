#!/bin/bash
# smart-update-reqs.sh - A script to install the smart auto-requirements updater

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/smart-update-reqs

# Create the main Python script
cat > ~/.local/bin/smart_update_requirements.py << 'EOF'
#!/usr/bin/env python3
"""
Smart Requirements Updater
Intelligently scans for Python projects and updates dependencies using dynamic analysis.
"""
import os
import re
import sys
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.error
import pkg_resources
import platform

# Configure logging
LOG_FILE = os.path.expanduser("~/.config/smart-update-reqs/update_log.txt")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Try to import additional packages, installing them if necessary
def ensure_package(package_name):
    try:
        return __import__(package_name)
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", package_name])
            return __import__(package_name)
        except:
            logging.warning(f"Could not install {package_name}. Some features may be limited.")
            return None

# Import optional packages for enhanced functionality
requests = ensure_package("requests")
packaging_version = ensure_package("packaging.version")
safety = ensure_package("safety")
packaging = ensure_package("packaging")

# Knowledge base of manual package replacements (fallback for when automatic detection fails)
FALLBACK_PACKAGE_REPLACEMENTS = {
    "pyaes": "pycryptodome",
    "pycrypto": "pycryptodome",
    "flask-script": "flask>=2.0.0",
    "django-smartpages": "django-flatpages",
    "python-memcached": "pymemcache",
    "mock": "pytest-mock",
    "nose": "pytest",
    "unittest2": "pytest",
}

# Initialize dynamic package knowledge base
PACKAGE_KNOWLEDGE_BASE_FILE = os.path.expanduser("~/.config/smart-update-reqs/package_knowledge.json")
if os.path.exists(PACKAGE_KNOWLEDGE_BASE_FILE):
    with open(PACKAGE_KNOWLEDGE_BASE_FILE, 'r') as f:
        try:
            PACKAGE_KNOWLEDGE_BASE = json.load(f)
        except json.JSONDecodeError:
            PACKAGE_KNOWLEDGE_BASE = {"replacements": {}, "deprecations": {}, "vulnerabilities": {}}
else:
    PACKAGE_KNOWLEDGE_BASE = {"replacements": {}, "deprecations": {}, "vulnerabilities": {}}

class PackageInfo:
    """Class to hold package information and provide comparison functionality."""
    def __init__(self, name, version_str=None, pypi_info=None):
        self.name = name.lower()
        self.version_str = version_str
        self.version = None if version_str is None else self._parse_version(version_str)
        self.pypi_info = pypi_info
        self.latest_version = None
        self.latest_version_str = None
        self.is_deprecated = False
        self.replacement = None
        self.vulnerabilities = []
        
    def _parse_version(self, version_str):
        """Parse version string to version object for comparison."""
        if packaging_version:
            try:
                return packaging_version.Version(version_str)
            except:
                return version_str
        return version_str
    
    def fetch_pypi_info(self):
        """Fetch package info from PyPI."""
        if not requests:
            return False
        
        try:
            response = requests.get(f"https://pypi.org/pypi/{self.name}/json", timeout=5)
            if response.status_code == 200:
                self.pypi_info = response.json()
                # Get latest version
                self.latest_version_str = self.pypi_info.get('info', {}).get('version')
                self.latest_version = self._parse_version(self.latest_version_str)
                
                # Check for deprecation hints
                info = self.pypi_info.get('info', {})
                description = info.get('description', '') or ''
                summary = info.get('summary', '') or ''
                
                deprecated_keywords = ['deprecated', 'no longer maintained', 'use instead', 'replaced by']
                
                for keyword in deprecated_keywords:
                    if keyword in description.lower() or keyword in summary.lower():
                        self.is_deprecated = True
                        # Try to find replacement suggestion
                        text = description + ' ' + summary
                        replace_patterns = [
                            r'use\s+([a-zA-Z0-9_-]+)\s+instead',
                            r'replaced\s+by\s+([a-zA-Z0-9_-]+)',
                            r'use\s+the\s+([a-zA-Z0-9_-]+)\s+package',
                            r'recommend\s+using\s+([a-zA-Z0-9_-]+)'
                        ]
                        
                        for pattern in replace_patterns:
                            match = re.search(pattern, text.lower())
                            if match:
                                self.replacement = match.group(1)
                                # Add to knowledge base
                                if self.replacement not in PACKAGE_KNOWLEDGE_BASE["replacements"]:
                                    PACKAGE_KNOWLEDGE_BASE["replacements"][self.name] = self.replacement
                                    _save_knowledge_base()
                                break
                
                return True
            return False
        except (requests.RequestException, json.JSONDecodeError):
            return False
    
    def check_for_vulnerabilities(self):
        """Check package for known vulnerabilities."""
        if safety:
            try:
                with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
                    tmp.write(f"{self.name}=={self.version_str}")
                    tmp_name = tmp.name
                
                try:
                    # Run safety check
                    result = subprocess.run(
                        [sys.executable, '-m', 'safety', 'check', '--file', tmp_name, '--json'],
                        capture_output=True, text=True
                    )
                    
                    if result.returncode != 0:
                        data = json.loads(result.stdout)
                        if isinstance(data, list):
                            self.vulnerabilities = data
                            
                            # Add to knowledge base
                            if self.vulnerabilities and self.name not in PACKAGE_KNOWLEDGE_BASE["vulnerabilities"]:
                                PACKAGE_KNOWLEDGE_BASE["vulnerabilities"][self.name] = {
                                    "version": self.version_str,
                                    "count": len(self.vulnerabilities)
                                }
                                _save_knowledge_base()
                            
                            return True
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
            except Exception as e:
                logging.debug(f"Error checking vulnerabilities for {self.name}: {e}")
        return False
    
    def needs_update(self):
        """Check if package needs update."""
        if self.latest_version and self.version:
            try:
                return self.latest_version > self.version
            except:
                # If comparison fails, use string comparison as fallback
                return self.latest_version_str != self.version_str
        return False
    
    def should_be_replaced(self):
        """Check if package should be replaced."""
        # Check knowledge base first
        if self.name in PACKAGE_KNOWLEDGE_BASE["replacements"]:
            self.replacement = PACKAGE_KNOWLEDGE_BASE["replacements"][self.name]
            return True
        
        # Check fallback replacements
        if self.name in FALLBACK_PACKAGE_REPLACEMENTS:
            self.replacement = FALLBACK_PACKAGE_REPLACEMENTS[self.name]
            return True
        
        # Check if we identified it as deprecated
        if self.is_deprecated and self.replacement:
            return True
        
        return False
    
    def get_update_spec(self):
        """Get updated package specification."""
        if self.should_be_replaced():
            # For replacements, we'll preserve any version constraints from the replacement info
            if '>=' in self.replacement or '==' in self.replacement:
                return self.replacement
            return f"{self.replacement}"
        elif self.needs_update():
            return f"{self.name}>={self.latest_version_str}"
        return None

def _save_knowledge_base():
    """Save the knowledge base to disk."""
    os.makedirs(os.path.dirname(PACKAGE_KNOWLEDGE_BASE_FILE), exist_ok=True)
    with open(PACKAGE_KNOWLEDGE_BASE_FILE, 'w') as f:
        json.dump(PACKAGE_KNOWLEDGE_BASE, f, indent=2)

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
    
    # Load config or create default
    config_file = os.path.expanduser("~/.config/smart-update-reqs/config.json")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "scan_directories": [os.path.expanduser("~")],
            "exclude_directories": [
                "~/anaconda3", "~/miniconda3", "~/venv", "~/.venv"
            ]
        }
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    # Expand all exclude directories
    expanded_exclude_dirs = []
    for exclude_dir in config.get("exclude_directories", []):
        expanded_exclude_dirs.append(os.path.expanduser(exclude_dir))
    
    logging.info(f"Scanning for Python projects in {start_dir}")
    
    for root, dirs, files in os.walk(start_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        # Skip directories from config
        if any(root.startswith(excluded) for excluded in expanded_exclude_dirs):
            dirs[:] = []
            continue
        
        # Check if this is a Python project
        for marker in project_markers:
            if marker in files:
                python_projects.append(root)
                logging.info(f"Found Python project: {root}")
                break
    
    return python_projects

def parse_requirements(requirements_file):
    """
    Parse a requirements.txt file and return a list of package specifications.
    """
    packages = []
    
    if not os.path.exists(requirements_file):
        return packages
    
    with open(requirements_file, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            packages.append({"type": "comment", "content": line})
            continue
        
        # Skip options (lines starting with -)
        if line.startswith('-'):
            packages.append({"type": "option", "content": line})
            continue
            
        # Handle environment markers
        if ';' in line:
            spec, env_marker = line.split(';', 1)
            packages.append({
                "type": "package", 
                "spec": spec.strip(), 
                "env_marker": env_marker.strip()
            })
            continue
            
        # Regular package specification
        packages.append({"type": "package", "spec": line, "env_marker": None})
            
    return packages

def parse_package_spec(spec):
    """
    Parse a package specification into name and version constraint.
    Returns (name, version_constraint, original_spec)
    """
    if not spec:
        return None, None, spec
    
    # Handle direct URL or path requirements
    if spec.startswith(('http://', 'https://', 'git+', 'file:')):
        return spec, None, spec
    
    # Handle egg fragments
    if '#egg=' in spec:
        spec = spec.split('#egg=')[1]
    
    # Extract package name and version constraints
    parts = re.split(r'(==|>=|<=|!=|~=|>|<|@)', spec, 1)
    
    if len(parts) >= 3:
        name = parts[0].strip()
        constraint = parts[1] + parts[2].strip()
        return name, constraint, spec
    
    # No version constraint
    return spec.strip(), None, spec

def check_and_update_package(pkg_info):
    """
    Check a package against PyPI and update its information.
    """
    # Skip if not a valid package name (like direct URLs)
    if not pkg_info or any(c in pkg_info.name for c in ":/\\"):
        return pkg_info
    
    # Check knowledge base first for cached info
    if pkg_info.name in PACKAGE_KNOWLEDGE_BASE.get("deprecations", {}):
        pkg_info.is_deprecated = True
        pkg_info.replacement = PACKAGE_KNOWLEDGE_BASE["replacements"].get(pkg_info.name)
    
    # Fetch from PyPI if we have network
    pkg_info.fetch_pypi_info()
    
    # Check for vulnerabilities if we have a version
    if pkg_info.version_str:
        pkg_info.check_for_vulnerabilities()
    
    return pkg_info

def update_requirements_file(requirements_file):
    """Update a requirements.txt file with modern equivalents."""
    if not os.path.exists(requirements_file):
        return False
    
    logging.info(f"Updating {requirements_file}")
    
    # Parse requirements file
    packages = parse_requirements(requirements_file)
    if not packages:
        logging.info(f"  No packages found in {requirements_file}")
        return False
    
    # Extract package info for actual packages
    pkg_infos = []
    for pkg in packages:
        if pkg["type"] == "package":
            name, version_constraint, original_spec = parse_package_spec(pkg["spec"])
            if name:
                version_str = version_constraint[2:] if version_constraint and '==' in version_constraint else None
                pkg_infos.append(PackageInfo(name, version_str))
    
    # Check packages in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        updated_pkg_infos = list(executor.map(check_and_update_package, pkg_infos))
    
    # Map back to package positions
    pkg_info_index = 0
    updated = False
    new_lines = []
    
    for pkg in packages:
        if pkg["type"] == "package":
            name, _, _ = parse_package_spec(pkg["spec"])
            if name:
                pkg_info = updated_pkg_infos[pkg_info_index]
                update_spec = pkg_info.get_update_spec()
                
                if update_spec:
                    # Create the updated line
                    if pkg["env_marker"]:
                        new_line = f"{update_spec}; {pkg['env_marker']}"
                    else:
                        new_line = update_spec
                    
                    new_lines.append(new_line)
                    updated = True
                    
                    if pkg_info.should_be_replaced():
                        logging.info(f"  Replaced {pkg_info.name} with {update_spec}")
                    else:
                        logging.info(f"  Updated {pkg_info.name} to {update_spec}")
                else:
                    # No update needed
                    if pkg["env_marker"]:
                        new_lines.append(f"{pkg['spec']}; {pkg['env_marker']}")
                    else:
                        new_lines.append(pkg["spec"])
                
                pkg_info_index += 1
            else:
                # Couldn't parse name, keep original
                if pkg["env_marker"]:
                    new_lines.append(f"{pkg['spec']}; {pkg['env_marker']}")
                else:
                    new_lines.append(pkg["spec"])
        else:
            # Comment or option, keep as is
            new_lines.append(pkg["content"])
    
    if updated:
        # Make a backup
        backup_file = f"{requirements_file}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        with open(backup_file, 'w') as f:
            with open(requirements_file, 'r') as original:
                f.write(original.read())
        
        # Write updated file
        with open(requirements_file, 'w') as f:
            f.write('\n'.join(new_lines))
        
        logging.info(f"  Updated {requirements_file}")
        return True
    else:
        logging.info(f"  No updates needed for {requirements_file}")
        return False

def process_python_project(project_dir):
    """Process a Python project directory for requirements updates."""
    logging.info(f"Processing project: {project_dir}")
    
    updates_made = False
    
    # Check for requirements.txt
    requirements_file = os.path.join(project_dir, "requirements.txt")
    if os.path.exists(requirements_file):
        if update_requirements_file(requirements_file):
            updates_made = True
    
    # Check for dev-requirements.txt
    dev_requirements_file = os.path.join(project_dir, "dev-requirements.txt")
    if os.path.exists(dev_requirements_file):
        if update_requirements_file(dev_requirements_file):
            updates_made = True
    
    # Check for test-requirements.txt
    test_requirements_file = os.path.join(project_dir, "test-requirements.txt")
    if os.path.exists(test_requirements_file):
        if update_requirements_file(test_requirements_file):
            updates_made = True
    
    # Check for requirements in a requirements directory
    req_dir = os.path.join(project_dir, "requirements")
    if os.path.exists(req_dir) and os.path.isdir(req_dir):
        for file in os.listdir(req_dir):
            if file.endswith(".txt"):
                if update_requirements_file(os.path.join(req_dir, file)):
                    updates_made = True
    
    return updates_made

def update_knowledge_base():
    """Update the package knowledge base from online sources."""
    if not requests:
        return False
    
    try:
        # Fetch known deprecated packages from PyPI
        response = requests.get("https://raw.githubusercontent.com/styrogenic/smart-reqs/main/deprecated_packages.json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            # Update our knowledge base
            for pkg, replacement in data.get("replacements", {}).items():
                if pkg not in PACKAGE_KNOWLEDGE_BASE["replacements"]:
                    PACKAGE_KNOWLEDGE_BASE["replacements"][pkg] = replacement
            
            for pkg in data.get("deprecated", []):
                if pkg not in PACKAGE_KNOWLEDGE_BASE["deprecations"]:
                    PACKAGE_KNOWLEDGE_BASE["deprecations"][pkg] = True
            
            # Save the updated knowledge base
            _save_knowledge_base()
            return True
    except:
        pass
    
    return False

def print_system_info():
    """Print information about the system."""
    logging.info(f"Python version: {platform.python_version()}")
    logging.info(f"Platform: {platform.platform()}")
    logging.info(f"Machine: {platform.machine()}")
    
    # Log package versions
    logging.info("Dependency versions:")
    deps = ["requests", "packaging", "safety"]
    for dep in deps:
        try:
            pkg = __import__(dep)
            version = getattr(pkg, "__version__", "unknown")
            logging.info(f"  {dep}: {version}")
        except ImportError:
            logging.info(f"  {dep}: not installed")

def main():
    """Main function to find and update Python projects."""
    logging.info("Starting smart requirements updater")
    
    # Print system info
    print_system_info()
    
    # Try to update the knowledge base
    update_knowledge_base()
    
    # Load config or create default
    config_file = os.path.expanduser("~/.config/smart-update-reqs/config.json")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "scan_directories": [os.path.expanduser("~")],
            "exclude_directories": [
                "~/anaconda3", "~/miniconda3", "~/venv", "~/.venv"
            ]
        }
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    projects_updated = 0
    projects_processed = 0
    
    # Process each scan directory
    for scan_dir in config["scan_directories"]:
        scan_dir = os.path.expanduser(scan_dir)
        if not os.path.exists(scan_dir):
            logging.warning(f"Scan directory does not exist: {scan_dir}")
            continue
        
        python_projects = find_python_projects(scan_dir)
        logging.info(f"Found {len(python_projects)} Python projects in {scan_dir}")
        
        # Expand excluded directories
        expanded_exclude_dirs = [os.path.expanduser(d) for d in config.get("exclude_directories", [])]
        
        for project in python_projects:
            # Skip excluded directories
            if any(project.startswith(exclude) for exclude in expanded_exclude_dirs):
                logging.info(f"Skipping excluded project: {project}")
                continue
            
            projects_processed += 1
            if process_python_project(project):
                projects_updated += 1
    
    logging.info(f"Completed processing {projects_processed} Python projects")
    logging.info(f"Updated {projects_updated} projects")

if __name__ == "__main__":
    main()
EOF

# Make the script executable
chmod +x ~/.local/bin/smart_update_requirements.py

# Create the systemd service file
cat > ~/.config/systemd/user/smart-update-reqs.service << 'EOF'
[Unit]
Description=Smart Update Python Requirements
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "~/.local/bin/smart_update_requirements.py"
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

# Create the timer unit to run at boot and periodically
cat > ~/.config/systemd/user/smart-update-reqs.timer << 'EOF'
[Unit]
Description=Run Smart Update Python Requirements Weekly

[Timer]
OnBootSec=2min
OnUnitActiveSec=1week
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Create initial config file
mkdir -p ~/.config/smart-update-reqs
cat > ~/.config/smart-update-reqs/config.json << 'EOF'
{
  "scan_directories": ["~/"],
  "exclude_directories": [
    "~/anaconda3", 
    "~/miniconda3", 
    "~/venv", 
    "~/.venv"
  ]
}
EOF

# Enable and start the timer
systemctl --user enable smart-update-reqs.timer
systemctl --user start smart-update-reqs.timer

echo "Smart requirements updater has been installed!"
echo "The script will run on boot and weekly thereafter"
echo "Configuration file: ~/.config/smart-update-reqs/config.json"
echo "Logs: ~/.config/smart-update-reqs/update_log.txt"
echo "To run manually: ~/.local/bin/smart_update_requirements.py"
