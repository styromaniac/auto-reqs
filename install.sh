#!/bin/bash
# enhanced-smart-update-reqs.sh - A script that implements a five-step process:
# 1. conda update
# 2. backup requirements files
# 3. update requirements files
# 4. build projects
# 5. provide a signal system for startup scripts

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/smart-update-reqs
mkdir -p ~/.config/smart-update-reqs/signals
mkdir -p ~/.config/smart-update-reqs/backups

# Create the main Python script
cat > ~/.local/bin/smart_update_requirements.py << 'EOF'
#!/usr/bin/env python3
"""
Enhanced Smart Requirements Updater
Implements a five-step workflow:
1. conda update - Update conda environments
2. backup requirements files - Create backups of all requirements files
3. update requirements files - Update package specifications
4. build projects - Rebuild projects after updates
5. provide a signal system - Signal when updates occur for startup scripts
"""
import os
import re
import sys
import json
import shutil
import logging
import subprocess
import tempfile
import time
import glob
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import urllib.request
import urllib.error
import pkg_resources
import platform
import hashlib
import signal

# Configure logging
LOG_FILE = os.path.expanduser("~/.config/smart-update-reqs/update_log.txt")
SIGNAL_DIR = os.path.expanduser("~/.config/smart-update-reqs/signals")
BACKUP_DIR = os.path.expanduser("~/.config/smart-update-reqs/backups")

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

# Make sure backup and signal directories exist
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(SIGNAL_DIR, exist_ok=True)

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

# ----- STEP 1: CONDA UPDATE FUNCTIONS -----

def update_conda_environments():
    """Update all conda environments."""
    logging.info("Starting conda environment updates")
    
    # Check if conda is available
    try:
        conda_info = subprocess.run(
            ["conda", "info", "--json"],
            capture_output=True, text=True, check=True
        )
        conda_data = json.loads(conda_info.stdout)
        
        # Update conda itself first
        logging.info("Updating conda base installation")
        subprocess.run(
            ["conda", "update", "-n", "base", "conda", "-y"],
            capture_output=True, text=True
        )
        
        # Get list of environments
        env_list = subprocess.run(
            ["conda", "env", "list", "--json"],
            capture_output=True, text=True, check=True
        )
        env_data = json.loads(env_list.stdout)
        
        # Update each environment
        for env in env_data.get("envs", []):
            env_name = os.path.basename(env)
            if env_name == "base":
                continue  # We already updated base
                
            logging.info(f"Updating conda environment: {env_name}")
            try:
                # Update all packages in the environment
                update_result = subprocess.run(
                    ["conda", "update", "--all", "-n", env_name, "-y"],
                    capture_output=True, text=True, timeout=600  # 10 minute timeout
                )
                
                if update_result.returncode == 0:
                    logging.info(f"Successfully updated conda environment: {env_name}")
                else:
                    logging.warning(f"Failed to update conda environment {env_name}: {update_result.stderr}")
                    
                # Signal that this environment was updated
                create_signal(f"conda_env_updated_{env_name}")
                
            except subprocess.TimeoutExpired:
                logging.error(f"Timeout updating conda environment: {env_name}")
            except Exception as e:
                logging.error(f"Error updating conda environment {env_name}: {str(e)}")
        
        return True
    except (subprocess.SubprocessError, json.JSONDecodeError) as e:
        logging.error(f"Error checking conda: {str(e)}")
        return False
    except FileNotFoundError:
        logging.info("Conda not found on this system")
        return False

# ----- STEP 2: BACKUP REQUIREMENTS FILES -----

def backup_requirements_file(file_path):
    """Create a backup of a requirements file."""
    if not os.path.exists(file_path):
        return False
        
    try:
        # Generate a unique filename based on the path and date
        filename = os.path.basename(file_path)
        parent_dir = os.path.basename(os.path.dirname(file_path))
        date_str = datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # Create a hash of the path to ensure uniqueness
        path_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        
        backup_filename = f"{parent_dir}_{filename}_{date_str}_{path_hash}.bak"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Copy the file
        shutil.copy2(file_path, backup_path)
        logging.info(f"Created backup of {file_path} at {backup_path}")
        return True
    except Exception as e:
        logging.error(f"Error backing up {file_path}: {str(e)}")
        return False

# ----- HELPERS FOR PROJECT FINDING AND PROCESSING -----

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
        "poetry.lock",
        "environment.yml",  # Conda environment file
        "conda-env.yml",    # Another common conda env filename
        ".python-version",  # pyenv
        "tox.ini"           # tox
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
            ],
            "build_after_update": True,
            "update_conda": True
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

# ----- STEP 3: UPDATE REQUIREMENTS FILES -----

def update_requirements_file(requirements_file):
    """Update a requirements.txt file with modern equivalents."""
    if not os.path.exists(requirements_file):
        return False
    
    logging.info(f"Updating {requirements_file}")
    
    # First, create a backup
    backup_requirements_file(requirements_file)
    
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
        # Write updated file
        with open(requirements_file, 'w') as f:
            f.write('\n'.join(new_lines))
        
        logging.info(f"  Updated {requirements_file}")
        return True
    else:
        logging.info(f"  No updates needed for {requirements_file}")
        return False

# ----- STEP 4: BUILD PROJECTS -----

def detect_project_type(project_dir):
    """Detect what type of Python project this is."""
    project_type = {
        "has_requirements": False,
        "has_setup_py": False,
        "has_pyproject": False,
        "has_pipfile": False,
        "has_conda_env": False,
        "venv_path": None,
        "conda_env_name": None
    }
    
    # Check for requirements.txt
    if os.path.exists(os.path.join(project_dir, "requirements.txt")):
        project_type["has_requirements"] = True
    
    # Check for setup.py
    if os.path.exists(os.path.join(project_dir, "setup.py")):
        project_type["has_setup_py"] = True
    
    # Check for pyproject.toml
    if os.path.exists(os.path.join(project_dir, "pyproject.toml")):
        project_type["has_pyproject"] = True
    
    # Check for Pipfile
    if os.path.exists(os.path.join(project_dir, "Pipfile")):
        project_type["has_pipfile"] = True
    
    # Check for conda environment files
    conda_files = ["environment.yml", "conda-env.yml", "conda.yml"]
    for conda_file in conda_files:
        if os.path.exists(os.path.join(project_dir, conda_file)):
            project_type["has_conda_env"] = True
            
            # Try to extract conda env name
            try:
                with open(os.path.join(project_dir, conda_file), 'r') as f:
                    for line in f:
                        if line.startswith("name:"):
                            project_type["conda_env_name"] = line.split(":", 1)[1].strip()
                            break
            except:
                pass
            
            break
    
    # Check for virtual environment in the project
    venv_dirs = ["venv", ".venv", "env", ".env"]
    for venv_dir in venv_dirs:
        venv_path = os.path.join(project_dir, venv_dir)
        if os.path.exists(venv_path) and os.path.isdir(venv_path):
            if os.path.exists(os.path.join(venv_path, "bin", "activate")) or \
               os.path.exists(os.path.join(venv_path, "Scripts", "activate.bat")):
                project_type["venv_path"] = venv_path
                break
    
    return project_type

def build_project(project_dir, updated_files):
    """
    Build or reinstall a project after its requirements have been updated.
    Returns True if build was successful, False otherwise.
    """
    if not updated_files:
        logging.info(f"No files were updated in {project_dir}, skipping build")
        return False
        
    logging.info(f"Building project in {project_dir}")
    
    # Detect project type
    project_type = detect_project_type(project_dir)
    
    build_commands = []
    build_env = os.environ.copy()
    
    # Handle conda environments
    if project_type["has_conda_env"] and project_type["conda_env_name"]:
        conda_env_name = project_type["conda_env_name"]
        logging.info(f"Rebuilding conda environment: {conda_env_name}")
        
        # Look for the conda environment file
        conda_file = None
        for filename in ["environment.yml", "conda-env.yml", "conda.yml"]:
            if os.path.exists(os.path.join(project_dir, filename)):
                conda_file = os.path.join(project_dir, filename)
                break
                
        if conda_file:
            # Check if environment exists
            try:
                env_check = subprocess.run(
                    ["conda", "env", "list", "--json"],
                    capture_output=True, text=True, check=True
                )
                env_data = json.loads(env_check.stdout)
                
                env_exists = any(
                    conda_env_name == os.path.basename(env) 
                    for env in env_data.get("envs", [])
                )
                
                if env_exists:
                    # Update existing environment
                    build_commands.append(
                        ["conda", "env", "update", "-n", conda_env_name, "-f", conda_file]
                    )
                else:
                    # Create new environment
                    build_commands.append(
                        ["conda", "env", "create", "-f", conda_file]
                    )
            except:
                logging.error(f"Error checking conda environments for {conda_env_name}")
        
    # Handle pip requirements in a virtual environment
    elif project_type["venv_path"] and project_type["has_requirements"]:
        venv_path = project_type["venv_path"]
        requirements_file = os.path.join(project_dir, "requirements.txt")
        
        # Determine path to pip executable in the venv
        if os.path.exists(os.path.join(venv_path, "bin", "pip")):
            pip_path = os.path.join(venv_path, "bin", "pip")
        elif os.path.exists(os.path.join(venv_path, "Scripts", "pip.exe")):
            pip_path = os.path.join(venv_path, "Scripts", "pip.exe")
        else:
            logging.error(f"Could not find pip in virtual environment {venv_path}")
            return False
            
        # Update packages in the virtual environment
        build_commands.append(
            [pip_path, "install", "-r", requirements_file, "--upgrade"]
        )
        
        # If it's an editable install, reinstall the project
        if project_type["has_setup_py"]:
            build_commands.append(
                [pip_path, "install", "-e", project_dir]
            )
            
    # Handle projects with setup.py but no dedicated venv
    elif project_type["has_setup_py"]:
        # Just run pip install -e . with the system Python
        build_commands.append(
            [sys.executable, "-m", "pip", "install", "-e", project_dir]
        )
            
    # Handle projects with pyproject.toml
    elif project_type["has_pyproject"]:
        # Check for poetry
        try:
            with open(os.path.join(project_dir, "pyproject.toml"), 'r') as f:
                content = f.read()
                if "tool.poetry" in content:
                    # It's a poetry project
                    build_commands.append(
                        ["poetry", "install", "--directory", project_dir]
                    )
                else:
                    # Generic pyproject.toml, try pip
                    build_commands.append(
                        [sys.executable, "-m", "pip", "install", "-e", project_dir]
                    )
        except:
            logging.error(f"Error reading pyproject.toml in {project_dir}")
            
    # Handle Pipfile projects
    elif project_type["has_pipfile"]:
        build_commands.append(
            ["pipenv", "install", "--dev"]
        )
        
    # Handle simple requirements.txt without a venv
    elif project_type["has_requirements"]:
        requirements_file = os.path.join(project_dir, "requirements.txt")
        build_commands.append(
            [sys.executable, "-m", "pip", "install", "-r", requirements_file, "--user"]
        )
    
    # Execute build commands
    success = True
    for cmd in build_commands:
        try:
            logging.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=project_dir,
                env=build_env,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                logging.info(f"Command succeeded: {' '.join(cmd)}")
            else:
                logging.error(f"Command failed: {' '.join(cmd)}")
                logging.error(f"Error output: {result.stderr}")
                success = False
                
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {' '.join(cmd)}")
            success = False
        except Exception as e:
            logging.error(f"Error executing {' '.join(cmd)}: {str(e)}")
            success = False
    
    # Create a signal file for successful builds
    if success:
        # Create a hash based on the project directory to make it unique
        project_hash = hashlib.md5(project_dir.encode()).hexdigest()[:8]
        create_signal(f"project_built_{project_hash}")
        
    return success

# ----- STEP 5: SIGNAL SYSTEM -----

def create_signal(signal_name):
    """Create a signal file that can be detected by startup scripts."""
    signal_file = os.path.join(SIGNAL_DIR, f"{signal_name}.signal")
    timestamp = datetime.now().isoformat()
    
    with open(signal_file, 'w') as f:
        f.write(timestamp)
    
    logging.info(f"Created signal: {signal_name}")
    return signal_file

def cleanup_old_signals(max_age_days=7):
    """Clean up old signal files."""
    now = datetime.now()
    count = 0
    
    for signal_file in os.listdir(SIGNAL_DIR):
        if signal_file.endswith(".signal"):
            file_path = os.path.join(SIGNAL_DIR, signal_file)
            file_age = now - datetime.fromtimestamp(os.path.getmtime(file_path))
            
            if file_age.days > max_age_days:
                try:
                    os.remove(file_path)
                    count += 1
                except:
                    pass
    
    if count > 0:
        logging.info(f"Cleaned up {count} old signal files")

def update_knowledge_base():
    """Update the package knowledge base from online sources."""
    if not requests:
        return False
    
    try:
        # Fetch known deprecated packages 
        response = requests.get(
            "https://raw.githubusercontent.com/styromaniac/smart-reqs/main/deprecated_packages.json", 
            timeout=5
        )
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

def process_python_project(project_dir):
    """Process a Python project directory for requirements updates."""
    logging.info(f"Processing project: {project_dir}")
    
    updated_files = []
    
    # Check for requirements.txt
    requirements_file = os.path.join(project_dir, "requirements.txt")
    if os.path.exists(requirements_file):
        if update_requirements_file(requirements_file):
            updated_files.append(requirements_file)
    
    # Check for dev-requirements.txt
    dev_requirements_file = os.path.join(project_dir, "dev-requirements.txt")
    if os.path.exists(dev_requirements_file):
        if update_requirements_file(dev_requirements_file):
            updated_files.append(dev_requirements_file)
    
    # Check for test-requirements.txt
    test_requirements_file = os.path.join(project_dir, "test-requirements.txt")
    if os.path.exists(test_requirements_file):
        if update_requirements_file(test_requirements_file):
            updated_files.append(test_requirements_file)
    
    # Check for requirements in a requirements directory
    req_dir = os.path.join(project_dir, "requirements")
    if os.path.exists(req_dir) and os.path.isdir(req_dir):
        for file in os.listdir(req_dir):
            if file.endswith(".txt"):
                req_file = os.path.join(req_dir, file)
                if update_requirements_file(req_file):
                    updated_files.append(req_file)
    
    # Build the project if files were updated
    if updated_files:
        # Create a "project updated" signal before building
        project_hash = hashlib.md5(project_dir.encode()).hexdigest()[:8]
        create_signal(f"project_updated_{project_hash}")
        
        # Get config to see if we should build
        config_file = os.path.expanduser("~/.config/smart-update-reqs/config.json")
        build_enabled = True
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                build_enabled = config.get("build_after_update", True)
        
        # Build if enabled
        if build_enabled:
            build_project(project_dir, updated_files)
    
    return len(updated_files) > 0

def main():
    """Main function to find and update Python projects."""
    logging.info("Starting enhanced smart requirements updater")
    
    # Print system info
    print_system_info()
    
    # Create a startup signal
    create_signal("updater_started")
    
    # Clean up old signals
    cleanup_old_signals()
    
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
            ],
            "build_after_update": True,
            "update_conda": True
        }
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    # STEP 1: Update conda if enabled
    if config.get("update_conda", True):
        update_conda_environments()
    
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
    
    # Create a completion signal
    create_signal("updater_completed")

if __name__ == "__main__":
    # Handle graceful termination
    def signal_handler(sig, frame):
        logging.info("Received termination signal, creating abort signal")
        create_signal("updater_aborted")
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
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
  ],
  "build_after_update": true,
  "update_conda": true
}
EOF

# Create startup script helper to check for signals
cat > ~/.local/bin/check-req-signals.sh << 'EOF'
#!/bin/bash
# Helper script to check for requirement update signals

SIGNAL_DIR=~/.config/smart-update-reqs/signals

# Function to check if a signal exists
check_signal() {
  local signal_name=$1
  local max_age_seconds=${2:-3600}  # Default: 1 hour
  
  # Find matching signal files
  for signal_file in "$SIGNAL_DIR"/${signal_name}*.signal; do
    if [ -f "$signal_file" ]; then
      # Check age
      file_mtime=$(stat -c %Y "$signal_file" 2>/dev/null || stat -f %m "$signal_file" 2>/dev/null)
      current_time=$(date +%s)
      age_seconds=$((current_time - file_mtime))
      
      if [ $age_seconds -le $max_age_seconds ]; then
        return 0  # Signal exists and is recent
      fi
    fi
  done
  
  return 1  # No recent signal found
}

# Check if any conda environment was updated
conda_updated() {
  check_signal "conda_env_updated_" "$@"
}

# Check if any project was updated
project_updated() {
  check_signal "project_updated_" "$@"
}

# Check if any project was built
project_built() {
  check_signal "project_built_" "$@"
}

# Check if updater is running
updater_running() {
  check_signal "updater_started" "$@" && ! check_signal "updater_completed" "$@" && ! check_signal "updater_aborted" "$@"
}

# Check specific conda environment
conda_env_updated() {
  local env_name=$1
  shift
  check_signal "conda_env_updated_${env_name}" "$@"
}

# Main functionality
case "$1" in
  --any-conda-updated)
    conda_updated "${2:-3600}" && echo "yes" || echo "no"
    ;;
  --any-project-updated)
    project_updated "${2:-3600}" && echo "yes" || echo "no"
    ;;
  --any-project-built)
    project_built "${2:-3600}" && echo "yes" || echo "no" 
    ;;
  --updater-running)
    updater_running "${2:-3600}" && echo "yes" || echo "no"
    ;;
  --conda-env-updated)
    if [ -z "$2" ]; then
      echo "Error: Please specify environment name" >&2
      exit 1
    fi
    conda_env_updated "$2" "${3:-3600}" && echo "yes" || echo "no"
    ;;
  --list-signals)
    ls -la "$SIGNAL_DIR"
    ;;
  --help|*)
    echo "Usage: $0 [OPTION]"
    echo "Check for requirement update signals."
    echo ""
    echo "Options:"
    echo "  --any-conda-updated [MAX_AGE]   Check if any conda environment was updated"
    echo "  --any-project-updated [MAX_AGE] Check if any project was updated"
    echo "  --any-project-built [MAX_AGE]   Check if any project was built"
    echo "  --updater-running [MAX_AGE]     Check if updater is currently running"
    echo "  --conda-env-updated ENV [MAX_AGE] Check if specific conda environment was updated"
    echo "  --list-signals                  List all signals" 
    echo ""
    echo "MAX_AGE is maximum age in seconds (default: 3600)"
    ;;
esac
EOF

chmod +x ~/.local/bin/check-req-signals.sh

# Enable and start the timer
systemctl --user enable smart-update-reqs.timer
systemctl --user start smart-update-reqs.timer

# Create a one-line example script for startup integration
cat > ~/example-startup-integration.sh << 'EOF'
#!/bin/bash
# Example of how to use the signal system in startup scripts

# Check if any conda environments were updated in the last hour
if [ "$(~/.local/bin/check-req-signals.sh --any-conda-updated 3600)" == "yes" ]; then
  echo "Conda environments were updated. Taking appropriate actions..."
  # Your startup logic here
fi

# Check if a specific conda environment was updated
if [ "$(~/.local/bin/check-req-signals.sh --conda-env-updated myenv 3600)" == "yes" ]; then
  echo "myenv was updated. Restarting services..."
  # Restart specific services that depend on this environment
fi

# Check if updater is currently running
if [ "$(~/.local/bin/check-req-signals.sh --updater-running)" == "yes" ]; then
  echo "Updater is currently running. Waiting before starting services..."
  # Add delay or wait logic
fi
EOF

chmod +x ~/example-startup-integration.sh

echo "Enhanced Smart Requirements Updater has been installed!"
echo "The script implements the five-step process:"
echo "1. conda update - Updates all conda environments"
echo "2. backup requirements files - Creates backups in ~/.config/smart-update-reqs/backups"
echo "3. update requirements files - Updates dependencies to latest versions"
echo "4. build projects - Rebuilds projects with updated requirements"
echo "5. signal system - Creates signals in ~/.config/smart-update-reqs/signals"
echo ""
echo "The script will run on boot and weekly thereafter"
echo "Configuration file: ~/.config/smart-update-reqs/config.json"
echo "Logs: ~/.config/smart-update-reqs/update_log.txt"
echo "To run manually: ~/.local/bin/smart_update_requirements.py"
echo ""
echo "Signal checking tool: ~/.local/bin/check-req-signals.sh"
echo "Example startup integration: ~/example-startup-integration.sh"
