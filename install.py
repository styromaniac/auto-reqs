#!/usr/bin/env python3
"""
Smart Requirements Updater - Fully OS-Agnostic Pure Python Implementation

A tool that automatically:
1. Updates conda environments if available
2. Backs up requirements files
3. Updates package dependencies
4. Builds projects (with custom build options)
5. Signals when updates occur

Designed to work on ANY operating system with Python, with no OS-specific assumptions.
"""

import os
import re
import sys
import json
import shutil
import logging
import argparse
import tempfile
import platform
import hashlib
import datetime
import subprocess
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import importlib.util

# --- Setup Constants ---
VERSION = "1.0.0"
APP_NAME = "smart_update_reqs"

# --- OS-Agnostic Path Handling ---
def get_user_data_dir():
    """Get a platform-agnostic user data directory without assuming OS types"""
    # First try environment variables (works on many systems)
    for env_var in ["XDG_DATA_HOME", "APPDATA", "HOME"]:
        if env_var in os.environ:
            if env_var == "XDG_DATA_HOME":
                return os.path.join(os.environ[env_var], APP_NAME)
            elif env_var == "APPDATA":
                return os.path.join(os.environ[env_var], APP_NAME)
            else:  # HOME
                # Try common patterns without assuming OS
                for pattern in [
                    os.path.join(os.environ[env_var], ".config", APP_NAME),  # Linux-like
                    os.path.join(os.environ[env_var], "Library", "Application Support", APP_NAME),  # macOS-like
                    os.path.join(os.environ[env_var], f".{APP_NAME}")  # Unix-like fallback
                ]:
                    # Use the first pattern that exists or can be created
                    try:
                        os.makedirs(pattern, exist_ok=True)
                        return pattern
                    except:
                        continue
                
                # Final fallback - just use a dot directory in HOME
                return os.path.join(os.environ[env_var], f".{APP_NAME}")
    
    # Ultimate fallback - use a directory relative to the script
    return os.path.abspath(os.path.join(os.path.dirname(__file__), f"data_{APP_NAME}"))

# Use pathlib for path operations (more OS-agnostic)
APP_DIR = Path(get_user_data_dir())
CONFIG_FILE = APP_DIR / "config.json"
LOGS_DIR = APP_DIR / "logs"
SIGNAL_DIR = APP_DIR / "signals"
BACKUP_DIR = APP_DIR / "backups"
KNOWLEDGE_BASE_FILE = APP_DIR / "package_knowledge.json"
LOG_FILE = LOGS_DIR / "update_log.txt"

# Ensure directories exist
for directory in [APP_DIR, LOGS_DIR, SIGNAL_DIR, BACKUP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(LOG_FILE)),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- Dependencies Management ---
# Define script dependencies and their replacements
SCRIPT_DEPENDENCIES = {
    # Core/recommended dependencies
    "requests": {
        "required": False,
        "replacements": [],
        "min_version": "2.20.0",
        "purpose": "Fetching package info from PyPI"
    },
    "packaging": {
        "required": False,
        "replacements": [],
        "min_version": "20.0",
        "purpose": "Version parsing and comparison"
    },
    "safety": {
        "required": False,
        "replacements": [],
        "min_version": "1.10.0",
        "purpose": "Security vulnerability scanning"
    },
    
    # Legacy dependencies and their modern replacements
    "distribute": {
        "required": False,
        "replacements": ["setuptools"],
        "min_version": "",
        "purpose": "Package distribution utilities (obsolete)"
    },
    "pycurl": {
        "required": False,
        "replacements": ["requests"],
        "min_version": "",
        "purpose": "HTTP requests (often problematic, requests is preferred)"
    },
    "urllib3": {
        "required": False,
        "replacements": ["requests"],
        "min_version": "",
        "purpose": "HTTP requests (requests is a higher-level alternative)"
    },
    "pyyaml": {
        "required": False,
        "replacements": [],
        "min_version": "5.1",  # Safe load issue was fixed in 5.1
        "purpose": "YAML parsing for conda environment files"
    }
}

def is_package_installed(package_name):
    """Check if a Python package is installed"""
    return importlib.util.find_spec(package_name) is not None

def get_package_version(package_name):
    """Get the version of an installed package"""
    if not is_package_installed(package_name):
        return None
    
    try:
        pkg = importlib.import_module(package_name)
        # Try different version attributes (packages use different conventions)
        for attr in ["__version__", "version", "VERSION"]:
            if hasattr(pkg, attr):
                return getattr(pkg, attr)
                
        # If not found, try using pkg_resources
        if is_package_installed("pkg_resources"):
            import pkg_resources
            return pkg_resources.get_distribution(package_name).version
    except Exception:
        pass
    
    return None

def safe_import(package_name):
    """Try to import a package, return None if not available"""
    if is_package_installed(package_name):
        return importlib.import_module(package_name)
    return None

def update_own_dependencies():
    """Update the script's own dependencies, handling replacements for obsolete packages"""
    if not is_command_available("pip") and not is_package_installed("pip"):
        logging.warning("pip not available. Cannot update dependencies.")
        return False
    
    python_exec = get_python_executable()
    deps_updated = False
    
    # First, handle obsolete packages - replace them with modern equivalents
    for package_name, info in SCRIPT_DEPENDENCIES.items():
        if info["replacements"] and is_package_installed(package_name):
            logging.info(f"Found obsolete package: {package_name}")
            
            # Try to uninstall the obsolete package
            try:
                subprocess.run(
                    [python_exec, "-m", "pip", "uninstall", "-y", package_name],
                    capture_output=True, text=True
                )
                logging.info(f"Uninstalled obsolete package: {package_name}")
                deps_updated = True
            except Exception as e:
                logging.warning(f"Failed to uninstall {package_name}: {e}")
            
            # Install the replacement(s)
            for replacement in info["replacements"]:
                if not is_package_installed(replacement):
                    try:
                        subprocess.run(
                            [python_exec, "-m", "pip", "install", "--user", replacement],
                            capture_output=True, text=True
                        )
                        logging.info(f"Installed replacement package: {replacement} (replaces {package_name})")
                        deps_updated = True
                    except Exception as e:
                        logging.warning(f"Failed to install replacement {replacement}: {e}")
    
    # Then, update or install missing dependencies
    for package_name, info in SCRIPT_DEPENDENCIES.items():
        if not info["replacements"]:  # Skip obsolete packages
            current_version = get_package_version(package_name)
            min_version = info["min_version"]
            
            needs_update = False
            if not current_version:
                needs_update = True  # Not installed
            elif min_version and packaging and packaging_version:
                try:
                    # Check if current version is less than minimum required
                    current_ver = packaging_version.Version(current_version)
                    min_ver = packaging_version.Version(min_version)
                    if current_ver < min_ver:
                        needs_update = True
                except Exception:
                    pass
            
            if needs_update:
                try:
                    # Install or upgrade
                    if min_version:
                        pkg_spec = f"{package_name}>={min_version}"
                    else:
                        pkg_spec = package_name
                        
                    subprocess.run(
                        [python_exec, "-m", "pip", "install", "--user", "--upgrade", pkg_spec],
                        capture_output=True, text=True
                    )
                    logging.info(f"Installed/updated dependency: {pkg_spec}")
                    deps_updated = True
                except Exception as e:
                    if info["required"]:
                        logging.error(f"Failed to install required dependency {package_name}: {e}")
                    else:
                        logging.warning(f"Failed to install optional dependency {package_name}: {e}")
    
    # If dependencies were updated, re-import them
    if deps_updated:
        global requests, safety, packaging, packaging_version
        requests = safe_import("requests")
        safety = safe_import("safety")
        packaging = safe_import("packaging")
        if packaging:
            packaging_version = safe_import("packaging.version")
    
    return deps_updated

# Import optional packages (will be updated or replaced later)
requests = safe_import("requests")
safety = safe_import("safety")
packaging = safe_import("packaging")
if packaging:
    packaging_version = safe_import("packaging.version")

# --- Knowledge Base ---
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

def load_knowledge_base():
    """Load the package knowledge base"""
    if KNOWLEDGE_BASE_FILE.exists():
        try:
            with open(KNOWLEDGE_BASE_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    
    # Default empty knowledge base
    return {
        "replacements": {},
        "deprecations": {},
        "vulnerabilities": {}
    }

def save_knowledge_base(knowledge_base):
    """Save the knowledge base to disk"""
    with open(KNOWLEDGE_BASE_FILE, 'w') as f:
        json.dump(knowledge_base, f, indent=2)

PACKAGE_KNOWLEDGE_BASE = load_knowledge_base()

# --- Configuration Management ---
def load_config():
    """Load configuration or create default"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Error parsing config file: {CONFIG_FILE}")
    
    # Create a default configuration
    config = {
        "scan_directories": [str(Path.home())],
        "exclude_directories": [
            str(Path.home() / "anaconda3"),
            str(Path.home() / "miniconda3"),
            str(Path.home() / "venv"),
            str(Path.home() / ".venv")
        ],
        "build_after_update": True,
        "build_strategy": "auto",
        "use_binary_packages": True,
        "binary_rootless_building": True,
        "update_conda": True,
        "custom_build_commands": {
            # Example: "zeronet": "python -m pip install -r {project_dir}/requirements.txt --no-build-isolation --user"
        }
    }
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    
    return config

# --- Signal System ---
def create_signal(signal_name):
    """Create a signal file that can be detected by startup scripts"""
    signal_file = SIGNAL_DIR / f"{signal_name}.signal"
    timestamp = datetime.datetime.now().isoformat()
    
    with open(signal_file, 'w') as f:
        f.write(timestamp)
    
    logging.info(f"Created signal: {signal_name}")
    return signal_file

def cleanup_old_signals(max_age_days=7):
    """Clean up old signal files"""
    now = datetime.datetime.now()
    count = 0
    
    for signal_file in SIGNAL_DIR.glob("*.signal"):
        file_age = now - datetime.datetime.fromtimestamp(signal_file.stat().st_mtime)
        
        if file_age.days > max_age_days:
            try:
                signal_file.unlink()
                count += 1
            except:
                pass
    
    if count > 0:
        logging.info(f"Cleaned up {count} old signal files")

def check_signal(signal_pattern, max_age_seconds=3600):
    """Check if a signal exists within the specified age"""
    now = time.time()
    
    for signal_file in SIGNAL_DIR.glob("*.signal"):
        if signal_pattern in signal_file.name:
            file_age = now - signal_file.stat().st_mtime
            
            if file_age <= max_age_seconds:
                return True
    
    return False

# --- Package Information ---
class PackageInfo:
    """Class to hold package information and provide comparison functionality"""
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
        """Parse version string to version object for comparison"""
        if packaging_version:
            try:
                return packaging_version.Version(version_str)
            except:
                return version_str
        return version_str
    
    def fetch_pypi_info(self):
        """Fetch package info from PyPI"""
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
                                    save_knowledge_base(PACKAGE_KNOWLEDGE_BASE)
                                break
                
                return True
            return False
        except Exception:
            return False
    
    def check_for_vulnerabilities(self):
        """Check package for known vulnerabilities"""
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
                                save_knowledge_base(PACKAGE_KNOWLEDGE_BASE)
                            
                            return True
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
            except Exception as e:
                logging.debug(f"Error checking vulnerabilities for {self.name}: {e}")
        return False
    
    def needs_update(self):
        """Check if package needs update"""
        if self.latest_version and self.version:
            try:
                return self.latest_version > self.version
            except:
                # If comparison fails, use string comparison as fallback
                return self.latest_version_str != self.version_str
        return False
    
    def should_be_replaced(self):
        """Check if package should be replaced"""
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
        """Get updated package specification"""
        if self.should_be_replaced():
            # For replacements, we'll preserve any version constraints from the replacement info
            if '>=' in self.replacement or '==' in self.replacement:
                return self.replacement
            return f"{self.replacement}"
        elif self.needs_update():
            return f"{self.name}>={self.latest_version_str}"
        return None

# --- File Handling Functions ---
def backup_requirements_file(file_path):
    """Create a backup of a requirements file"""
    file_path = Path(file_path)
    if not file_path.exists():
        return False
        
    try:
        # Generate a unique filename based on the path and date
        filename = file_path.name
        parent_dir = file_path.parent.name
        date_str = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # Create a hash of the path to ensure uniqueness
        path_hash = hashlib.md5(str(file_path).encode()).hexdigest()[:8]
        
        backup_filename = f"{parent_dir}_{filename}_{date_str}_{path_hash}.bak"
        backup_path = BACKUP_DIR / backup_filename
        
        # Copy the file
        shutil.copy2(file_path, backup_path)
        logging.info(f"Created backup of {file_path} at {backup_path}")
        return True
    except Exception as e:
        logging.error(f"Error backing up {file_path}: {str(e)}")
        return False

def parse_requirements(requirements_file):
    """Parse a requirements.txt file"""
    packages = []
    
    requirements_file = Path(requirements_file)
    if not requirements_file.exists():
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
    """Parse a package specification into name and version constraint"""
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
    """Check a package against PyPI and update its information"""
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
    """Update a requirements.txt file with modern equivalents"""
    requirements_file = Path(requirements_file)
    if not requirements_file.exists():
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

# --- Project Detection ---
def is_excluded(path, exclude_patterns):
    """Check if a path matches any exclusion pattern"""
    path = Path(path)
    for pattern in exclude_patterns:
        pattern = Path(os.path.expanduser(pattern))
        try:
            # resolve() follows symlinks, which might not be what we want,
            # but we use it here to get absolute paths
            if path.resolve().is_relative_to(pattern.resolve()):
                return True
        except (ValueError, OSError):  # is_relative_to can raise these errors
            # Try string-based comparison as fallback
            if str(path).startswith(str(pattern)):
                return True
    return False

def find_python_projects(config):
    """Find all Python projects in the specified directories"""
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
    
    # Directories to exclude by default (without assuming OS)
    default_exclude_dirs = [
        ".git", ".svn", ".hg",
        "node_modules", "venv", "env",
        ".venv", ".env", "__pycache__",
        ".pytest_cache", ".tox", 
        "build", "dist", ".eggs"
    ]
    
    # Start scan for each directory in config
    for scan_dir in config["scan_directories"]:
        scan_dir = Path(os.path.expanduser(scan_dir))
        if not scan_dir.exists():
            logging.warning(f"Scan directory does not exist: {scan_dir}")
            continue
            
        logging.info(f"Scanning for Python projects in {scan_dir}")
        
        # Use Path.rglob for path traversal
        for root, dirs, files in os.walk(str(scan_dir)):
            root_path = Path(root)
            
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in default_exclude_dirs]
            
            # Skip directories in config's exclude_directories
            if is_excluded(root_path, config.get("exclude_directories", [])):
                dirs[:] = []  # Don't traverse subdirectories
                continue
            
            # Check if this is a Python project
            for marker in project_markers:
                marker_path = root_path / marker
                if marker_path.exists():
                    python_projects.append(root_path)
                    logging.info(f"Found Python project: {root_path}")
                    break
    
    logging.info(f"Found {len(python_projects)} Python projects")
    return python_projects

def find_executable_path(root_dir, script_name):
    """Find an executable script in a directory without assuming OS-specific extensions"""
    # Try with common executable extensions
    for ext in ["", ".sh", ".bat", ".cmd", ".py", ".exe"]:
        script_path = Path(root_dir) / f"{script_name}{ext}"
        if script_path.exists() and os.access(script_path, os.X_OK):
            return script_path
    return None

def detect_project_type(project_dir):
    """Detect what type of Python project this is"""
    project_dir = Path(project_dir)
    project_type = {
        "has_requirements": False,
        "has_setup_py": False,
        "has_pyproject": False,
        "has_pipfile": False,
        "has_conda_env": False,
        "has_custom_build": False,
        "venv_path": None,
        "conda_env_name": None,
        "custom_build_script": None
    }
    
    # Check for custom build script first - highest priority
    custom_build_scripts = [
        "build", "build_project", "install", 
        "setup", "rebuild", "update_deps"
    ]
    for script_base in custom_build_scripts:
        script_path = find_executable_path(project_dir, script_base)
        if script_path:
            project_type["has_custom_build"] = True
            project_type["custom_build_script"] = script_path
            break
    
    # Check for standard Python project files
    req_file = project_dir / "requirements.txt"
    if req_file.exists():
        project_type["has_requirements"] = True
    
    setup_file = project_dir / "setup.py"
    if setup_file.exists():
        project_type["has_setup_py"] = True
    
    pyproject_file = project_dir / "pyproject.toml"
    if pyproject_file.exists():
        project_type["has_pyproject"] = True
    
    pipfile = project_dir / "Pipfile"
    if pipfile.exists():
        project_type["has_pipfile"] = True
    
    # Check for conda environment files
    conda_files = ["environment.yml", "conda-env.yml", "conda.yml"]
    for conda_file in conda_files:
        conda_path = project_dir / conda_file
        if conda_path.exists():
            project_type["has_conda_env"] = True
            
            # Try to extract conda env name
            try:
                with open(conda_path, 'r') as f:
                    for line in f:
                        if line.startswith("name:"):
                            project_type["conda_env_name"] = line.split(":", 1)[1].strip()
                            break
            except:
                pass
            
            break
    
    # Check for virtual environment in project directory
    # This is OS-agnostic - we look for common venv patterns
    venv_dirs = ["venv", ".venv", "env", ".env"]
    for venv_dir in venv_dirs:
        venv_path = project_dir / venv_dir
        if venv_path.exists() and venv_path.is_dir():
            # Check for common venv indicators in a cross-platform way
            venv_indicators = [
                venv_path / "bin" / "python",
                venv_path / "bin" / "activate",
                venv_path / "Scripts" / "python.exe",
                venv_path / "Scripts" / "activate.bat",
                venv_path / "pyvenv.cfg"
            ]
            
            for indicator in venv_indicators:
                if indicator.exists():
                    project_type["venv_path"] = venv_path
                    break
            
            if project_type["venv_path"]:
                break
    
    return project_type

# --- Build System ---
def is_command_available(command):
    """Check if a command is available without assuming shell type"""
    try:
        # Try to get command version/help - this should work for most commands
        result = subprocess.run(
            [command, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except FileNotFoundError:
        try:
            # Try with help flag as fallback
            result = subprocess.run(
                [command, "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

def get_python_executable():
    """Get the Python executable path in an OS-agnostic way"""
    return sys.executable

def find_executable_in_venv(venv_path, exec_name):
    """Find an executable in a virtual environment in an OS-agnostic way"""
    venv_path = Path(venv_path)
    
    # Check bin directory (Unix-like)
    bin_exec = venv_path / "bin" / exec_name
    if bin_exec.exists() and os.access(bin_exec, os.X_OK):
        return bin_exec
    
    # Check Scripts directory (Windows-like)
    for ext in ["", ".exe", ".cmd", ".bat"]:
        script_exec = venv_path / "Scripts" / f"{exec_name}{ext}"
        if script_exec.exists() and os.access(script_exec, os.X_OK):
            return script_exec
    
    return None

def update_conda_environments():
    """Update all conda environments in an OS-agnostic way"""
    if not is_command_available("conda"):
        logging.info("Conda not available. Skipping conda updates.")
        return False
    
    logging.info("Starting conda environment updates")
    
    # Check conda info
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
            env_path = Path(env)
            env_name = env_path.name
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
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
        logging.error(f"Error with conda: {str(e)}")
        return False

def build_project(project_dir, updated_files, config):
    """Build or reinstall a project after its requirements have been updated"""
    project_dir = Path(project_dir)
    if not updated_files:
        logging.info(f"No files were updated in {project_dir}, skipping build")
        return False
    
    # Get build preferences from config
    build_enabled = config.get("build_after_update", True)
    build_strategy = config.get("build_strategy", "auto")
    use_binary_packages = config.get("use_binary_packages", True)
    binary_rootless_building = config.get("binary_rootless_building", True)
    custom_build_commands = config.get("custom_build_commands", {})
    
    if not build_enabled:
        logging.info(f"Building is disabled in config, skipping build for {project_dir}")
        
        # Create a project updated signal, even though we're not building
        project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
        create_signal(f"project_updated_{project_hash}")
        return True
    
    logging.info(f"Building project in {project_dir}")
    
    # Detect project type
    project_type = detect_project_type(project_dir)
    
    # Check for project-specific build command in config
    for proj_pattern, cmd_template in custom_build_commands.items():
        if proj_pattern in str(project_dir) or (proj_pattern.startswith("re:") and re.search(proj_pattern[3:], str(project_dir))):
            logging.info(f"Using custom build command from config for {project_dir}")
            cmd = cmd_template.replace("{project_dir}", str(project_dir))
            
            # Execute the custom command - works on any OS with shell
            try:
                result = subprocess.run(
                    cmd, 
                    shell=True,
                    capture_output=True, 
                    text=True, 
                    cwd=project_dir
                )
                success = result.returncode == 0
                
                if success:
                    logging.info(f"Custom build command succeeded: {cmd}")
                    project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
                    create_signal(f"project_updated_{project_hash}")
                    create_signal(f"project_built_{project_hash}")
                    return True
                else:
                    logging.error(f"Custom build command failed: {cmd}")
                    logging.error(f"Error output: {result.stderr}")
                    
                    # Create an update signal even though build failed
                    project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
                    create_signal(f"project_updated_{project_hash}")
                    create_signal(f"project_build_failed_{project_hash}")
                    return False
            except Exception as e:
                logging.error(f"Error executing custom build command: {str(e)}")
                project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
                create_signal(f"project_updated_{project_hash}")
                create_signal(f"project_build_failed_{project_hash}")
                return False
    
    # Look for project-specific build script
    if project_type["has_custom_build"]:
        logging.info(f"Using project's custom build script: {project_type['custom_build_script']}")
        try:
            script_path = str(project_type['custom_build_script'])
            # Execute the script in a cross-platform way
            result = subprocess.run(
                [script_path], 
                capture_output=True, 
                text=True, 
                cwd=project_dir
            )
            success = result.returncode == 0
            
            if success:
                logging.info(f"Project build script succeeded: {script_path}")
                # Create signals after successful build
                project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
                create_signal(f"project_updated_{project_hash}")
                create_signal(f"project_built_{project_hash}")
                return True
            else:
                logging.error(f"Project build script failed: {script_path}")
                logging.error(f"Error output: {result.stderr}")
                # Create update signal even though build failed
                project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
                create_signal(f"project_updated_{project_hash}")
                create_signal(f"project_build_failed_{project_hash}")
                return False
        except Exception as e:
            logging.error(f"Error executing project build script: {str(e)}")
            project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
            create_signal(f"project_updated_{project_hash}")
            create_signal(f"project_build_failed_{project_hash}")
            return False
    
    # If build strategy is set to "skip" and no custom script exists, skip automatic building
    if build_strategy.lower() == "skip":
        logging.info(f"Build strategy set to 'skip' and no custom build script found, skipping build for {project_dir}")
        project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
        create_signal(f"project_updated_{project_hash}")
        return True
    
    # For "notify_only" strategy, just create a signal without building
    if build_strategy.lower() == "notify_only":
        logging.info(f"Build strategy set to 'notify_only', creating update signal for {project_dir}")
        project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
        create_signal(f"project_updated_{project_hash}")
        return True
    
    # If we get here, we'll use automatic build logic
    build_commands = []
    
    # Add binary package options if enabled
    binary_options = []
    if use_binary_packages:
        if binary_rootless_building:
            # Architecture agnostic binary options - no platform specifiers
            binary_options = ["--only-binary=:all:"]
            logging.info("Using binary rootless building options (architecture agnostic)")
        else:
            binary_options = ["--prefer-binary"]
            logging.info("Preferring binary packages when available")
    
    # Handle conda environments
    if project_type["has_conda_env"] and project_type["conda_env_name"] and is_command_available("conda"):
        conda_env_name = project_type["conda_env_name"]
        logging.info(f"Rebuilding conda environment: {conda_env_name}")
        
        # Look for the conda environment file
        conda_file = None
        for filename in ["environment.yml", "conda-env.yml", "conda.yml"]:
            conda_path = project_dir / filename
            if conda_path.exists():
                conda_file = conda_path
                break
                
        if conda_file:
            # Check if environment exists
            try:
                env_check = subprocess.run(
                    ["conda", "env", "list", "--json"],
                    capture_output=True, text=True, check=True
                )
                env_data = json.loads(env_check.stdout)
                
                env_exists = False
                for env in env_data.get("envs", []):
                    env_path = Path(env)
                    if env_path.name == conda_env_name:
                        env_exists = True
                        break
                
                if env_exists:
                    # Update existing environment
                    cmd = ["conda", "env", "update", "-n", conda_env_name, "-f", str(conda_file)]
                    if use_binary_packages:
                        cmd.extend(["--solver", "libmamba"])
                    build_commands.append(cmd)
                else:
                    # Create new environment
                    cmd = ["conda", "env", "create", "-f", str(conda_file)]
                    if use_binary_packages:
                        cmd.extend(["--solver", "libmamba"])
                    build_commands.append(cmd)
            except Exception as e:
                logging.error(f"Error checking conda environments for {conda_env_name}: {str(e)}")
        
    # Handle pip requirements in a virtual environment
    elif project_type["venv_path"] and project_type["has_requirements"]:
        venv_path = project_type["venv_path"]
        requirements_file = project_dir / "requirements.txt"
        
        # Find pip executable in the venv
        pip_path = find_executable_in_venv(venv_path, "pip")
        
        if not pip_path:
            logging.error(f"Could not find pip in virtual environment {venv_path}")
            # Create update signal even though build will fail
            project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
            create_signal(f"project_updated_{project_hash}")
            create_signal(f"project_build_failed_{project_hash}")
            return False
            
        # Update packages in the virtual environment
        cmd = [str(pip_path), "install", "-r", str(requirements_file), "--upgrade"]
        if binary_options:
            cmd.extend(binary_options)
        build_commands.append(cmd)
        
        # If it's an editable install, reinstall the project
        if project_type["has_setup_py"]:
            build_commands.append(
                [str(pip_path), "install", "-e", str(project_dir)]
            )
            
    # Handle projects with setup.py but no dedicated venv
    elif project_type["has_setup_py"] and is_command_available("pip") or is_package_installed("pip"):
        # Just run pip install -e . with the system Python
        python_exec = get_python_executable()
        cmd = [python_exec, "-m", "pip", "install", "-e", str(project_dir)]
        if binary_options:
            cmd.extend(binary_options)
        build_commands.append(cmd)
            
    # Handle projects with pyproject.toml
    elif project_type["has_pyproject"] and (is_command_available("pip") or is_package_installed("pip")):
        # Check for poetry
        try:
            with open(project_dir / "pyproject.toml", 'r') as f:
                content = f.read()
                if "tool.poetry" in content and is_command_available("poetry"):
                    # It's a poetry project
                    build_commands.append(
                        ["poetry", "install", "--directory", str(project_dir)]
                    )
                else:
                    # Generic pyproject.toml, try pip
                    python_exec = get_python_executable()
                    cmd = [python_exec, "-m", "pip", "install", "-e", str(project_dir)]
                    if binary_options:
                        cmd.extend(binary_options)
                    build_commands.append(cmd)
        except Exception as e:
            logging.error(f"Error reading pyproject.toml in {project_dir}: {str(e)}")
            
    # Handle Pipfile projects
    elif project_type["has_pipfile"] and is_command_available("pipenv"):
        build_commands.append(
            ["pipenv", "install", "--dev"]
        )
        
    # Handle simple requirements.txt without a venv
    elif project_type["has_requirements"] and (is_command_available("pip") or is_package_installed("pip")):
        requirements_file = project_dir / "requirements.txt"
        python_exec = get_python_executable()
        cmd = [python_exec, "-m", "pip", "install", "-r", str(requirements_file), "--user"]
        if binary_options:
            cmd.extend(binary_options)
        build_commands.append(cmd)
    
    # Create the project updated signal before attempting to build
    project_hash = hashlib.md5(str(project_dir).encode()).hexdigest()[:8]
    create_signal(f"project_updated_{project_hash}")
    
    # No build commands defined
    if not build_commands:
        logging.info(f"No build commands identified for {project_dir}")
        return False
    
    # Execute build commands
    success = True
    for cmd in build_commands:
        try:
            # Convert all arguments to strings for cross-platform compatibility
            cmd = [str(arg) for arg in cmd]
            logging.info(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=project_dir,
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
    
    # Create signals after build attempt
    if success:
        create_signal(f"project_built_{project_hash}")
    else:
        create_signal(f"project_build_failed_{project_hash}")
        
    return success

def process_python_project(project_dir, config):
    """Process a Python project directory for requirements updates"""
    project_dir = Path(project_dir)
    logging.info(f"Processing project: {project_dir}")
    
    updated_files = []
    
    # Check for requirements.txt
    requirements_file = project_dir / "requirements.txt"
    if requirements_file.exists():
        if update_requirements_file(requirements_file):
            updated_files.append(requirements_file)
    
    # Check for dev-requirements.txt
    dev_requirements_file = project_dir / "dev-requirements.txt"
    if dev_requirements_file.exists():
        if update_requirements_file(dev_requirements_file):
            updated_files.append(dev_requirements_file)
    
    # Check for test-requirements.txt
    test_requirements_file = project_dir / "test-requirements.txt"
    if test_requirements_file.exists():
        if update_requirements_file(test_requirements_file):
            updated_files.append(test_requirements_file)
    
    # Check for requirements in a requirements directory
    req_dir = project_dir / "requirements"
    if req_dir.exists() and req_dir.is_dir():
        for file_path in req_dir.glob("*.txt"):
            if update_requirements_file(file_path):
                updated_files.append(file_path)
    
    # Build the project if files were updated
    if updated_files:
        build_project(project_dir, updated_files, config)
    
    return len(updated_files) > 0

def update_knowledge_base_from_web():
    """Update the package knowledge base from online sources"""
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
            save_knowledge_base(PACKAGE_KNOWLEDGE_BASE)
            return True
    except Exception:
        pass
    
    return False

def print_system_info():
    """Print information about the system without assuming OS"""
    logging.info(f"Python version: {sys.version}")
    logging.info(f"Platform info: {platform.platform()}")
    
    # Log script dependency information
    logging.info("Script dependency status:")
    for package_name, info in SCRIPT_DEPENDENCIES.items():
        installed = is_package_installed(package_name)
        if installed:
            version = get_package_version(package_name)
            status = f"installed (version: {version or 'unknown'})"
            
            # Check if obsolete
            if info["replacements"]:
                status += f" - OBSOLETE, should be replaced with: {', '.join(info['replacements'])}"
            # Check if needs update
            elif info["min_version"] and version and packaging and packaging_version:
                try:
                    current_ver = packaging_version.Version(version)
                    min_ver = packaging_version.Version(info["min_version"])
                    if current_ver < min_ver:
                        status += f" - UPDATE RECOMMENDED (min: {info['min_version']})"
                except Exception:
                    pass
        else:
            if info["required"]:
                status = "MISSING (REQUIRED)"
            else:
                status = "not installed (optional)"
                if info["replacements"]:
                    replacements_installed = [r for r in info["replacements"] if is_package_installed(r)]
                    if replacements_installed:
                        status += f" - replacement(s) installed: {', '.join(replacements_installed)}"
        
        logging.info(f"  {package_name}: {status} - {info['purpose']}")
    
    # Log build tool availability
    logging.info("Build tool availability:")
    logging.info(f"  pip module: {is_package_installed('pip')}")
    logging.info(f"  pip command: {is_command_available('pip')}")
    logging.info(f"  conda command: {is_command_available('conda')}")
    logging.info(f"  poetry command: {is_command_available('poetry')}")
    logging.info(f"  pipenv command: {is_command_available('pipenv')}")

def generate_signal_checker():
    """Generate a simple, cross-platform signal checker script"""
    checker_path = APP_DIR / "check_signals.py"
    
    script_content = """#!/usr/bin/env python3
import os
import sys
import time
import argparse
import hashlib
from pathlib import Path

# Get the path to this script's directory
SCRIPT_DIR = Path(__file__).parent.absolute()
SIGNAL_DIR = SCRIPT_DIR / "signals"

def check_signal(signal_pattern, max_age_seconds=3600):
    """Check if a signal exists within the specified age"""
    if not SIGNAL_DIR.exists():
        return False
        
    now = time.time()
    
    for signal_file in SIGNAL_DIR.glob("*.signal"):
        if signal_pattern in signal_file.name:
            file_age = now - signal_file.stat().st_mtime
            
            if file_age <= max_age_seconds:
                return True
    
    return False

def project_hash(project_path):
    """Generate a hash for a project path"""
    return hashlib.md5(str(Path(project_path).absolute()).encode()).hexdigest()[:8]

def main():
    parser = argparse.ArgumentParser(description="Check for requirement update signals")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--any-conda-updated", action="store_true", help="Check if any conda environment was updated")
    group.add_argument("--any-project-updated", action="store_true", help="Check if any project was updated")
    group.add_argument("--any-project-built", action="store_true", help="Check if any project was built")
    group.add_argument("--any-project-build-failed", action="store_true", help="Check if any project build failed")
    group.add_argument("--updater-running", action="store_true", help="Check if updater is currently running")
    group.add_argument("--conda-env-updated", metavar="ENV", help="Check if specific conda environment was updated")
    group.add_argument("--project-status", metavar="PATH", help="Check status of specific project")
    group.add_argument("--list-signals", action="store_true", help="List all signals")
    
    parser.add_argument("--status-type", choices=["updated", "built"], default="built", 
                        help="Status type to check (for --project-status)")
    parser.add_argument("--max-age", type=int, default=3600, 
                        help="Maximum age in seconds (default: 3600)")
    
    args = parser.parse_args()
    
    # Check for signals directory
    if not SIGNAL_DIR.exists():
        print("error:no_signals_directory")
        return 1
    
    # Process the arguments
    if args.any_conda_updated:
        result = check_signal("conda_env_updated_", args.max_age)
        print("yes" if result else "no")
    
    elif args.any_project_updated:
        result = check_signal("project_updated_", args.max_age)
        print("yes" if result else "no")
    
    elif args.any_project_built:
        result = check_signal("project_built_", args.max_age)
        print("yes" if result else "no")
    
    elif args.any_project_build_failed:
        result = check_signal("project_build_failed_", args.max_age)
        print("yes" if result else "no")
    
    elif args.updater_running:
        started = check_signal("updater_started", args.max_age)
        completed = check_signal("updater_completed", args.max_age)
        aborted = check_signal("updater_aborted", args.max_age)
        
        result = started and not (completed or aborted)
        print("yes" if result else "no")
    
    elif args.conda_env_updated:
        result = check_signal(f"conda_env_updated_{args.conda_env_updated}", args.max_age)
        print("yes" if result else "no")
    
    elif args.project_status:
        path = Path(args.project_status)
        if not path.exists():
            print("error:path_not_found")
            return 1
            
        proj_hash = project_hash(path)
        
        if args.status_type == "updated":
            if check_signal(f"project_updated_{proj_hash}", args.max_age):
                print("updated")
            else:
                print("unchanged")
        else:  # built
            if check_signal(f"project_built_{proj_hash}", args.max_age):
                print("built")
            elif check_signal(f"project_build_failed_{proj_hash}", args.max_age):
                print("build_failed")
            elif check_signal(f"project_updated_{proj_hash}", args.max_age):
                print("updated_only")
            else:
                print("unchanged")
    
    elif args.list_signals:
        if SIGNAL_DIR.exists():
            for signal_file in sorted(SIGNAL_DIR.glob("*.signal")):
                file_time = time.strftime("%Y-%m-%d %H:%M:%S", 
                                         time.localtime(signal_file.stat().st_mtime))
                print(f"{signal_file.name} - {file_time}")
        else:
            print("error:no_signals_directory")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
    
    with open(checker_path, 'w') as f:
        f.write(script_content)
    
    # Try to make it executable - this may not work on all platforms
    try:
        os.chmod(checker_path, 0o755)
    except:
        pass
    
    logging.info(f"Generated signal checker script: {checker_path}")
    return checker_path

def generate_example_script():
    """Generate an example integration script that works on most platforms"""
    # Create a Python script instead of shell script - more portable
    script_path = APP_DIR / "example_integration.py"
    
    script_content = """#!/usr/bin/env python3
# Example of how to use the signal system in startup scripts

import os
import sys
import subprocess
from pathlib import Path

# Get the path to the check_signals.py script
SCRIPT_DIR = Path(__file__).parent.absolute()
CHECKER_SCRIPT = SCRIPT_DIR / "check_signals.py"

def run_checker(args):
    """Run the signal checker with arguments"""
    cmd = [sys.executable, str(CHECKER_SCRIPT)] + args.split()
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()

# Check if any conda environments were updated in the last hour
if run_checker("--any-conda-updated --max-age 3600") == "yes":
    print("Conda environments were updated. Taking appropriate actions...")
    # Your startup logic here

# Check if a specific conda environment was updated
if run_checker("--conda-env-updated myenv --max-age 3600") == "yes":
    print("myenv was updated. Restarting services...")
    # Restart specific services that depend on this environment

# Check the status of a specific project
project_path = os.path.expanduser("~/myproject")  # Change this to your project path
project_status = run_checker(f"--project-status {project_path} --status-type built --max-age 3600")

if project_status == "built":
    print("Project was successfully built. Starting services...")
    # Start services that depend on this project
elif project_status == "build_failed":
    print("Project build failed. Using previous version...")
    # Use fallback or notify admin
elif project_status == "updated_only":
    print("Project was updated but not built. May need manual intervention...")
    # Notify admin or trigger manual build

# Check if updater is currently running
if run_checker("--updater-running") == "yes":
    print("Updater is currently running. Waiting before starting services...")
    # Add delay or wait logic

# Check if any builds failed, might need manual intervention
if run_checker("--any-project-build-failed --max-age 86400") == "yes":
    print("WARNING: Some project builds failed in the last 24 hours!")
    # Send notification or create alert
"""
    
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Try to make it executable - this may not work on all platforms
    try:
        os.chmod(script_path, 0o755)
    except:
        pass
    
    logging.info(f"Generated example integration script: {script_path}")
    return script_path

# --- Main Function ---
def main():
    """Main function to find and update Python projects"""
    parser = argparse.ArgumentParser(description="Smart Requirements Updater")
    
    parser.add_argument("--version", action="version", version=f"Smart Requirements Updater v{VERSION}")
    parser.add_argument("--dry-run", action="store_true", help="Scan for updates but don't apply them")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--setup", action="store_true", help="Create helper tools without running updates")
    parser.add_argument("--update-self", action="store_true", help="Update the script's own dependencies")
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Update the script's own dependencies if requested
    if args.update_self:
        logging.info("Updating script dependencies...")
        if update_own_dependencies():
            logging.info("Script dependencies updated successfully")
            print("Script dependencies updated successfully. Please run the script again.")
            return 0
        else:
            logging.info("No updates needed for script dependencies")
    
    # Generate helper tools if requested
    if args.setup:
        signal_checker = generate_signal_checker()
        example_script = generate_example_script()
        
        print(f"Smart Requirements Updater v{VERSION} setup completed successfully!")
        print(f"Configuration file: {CONFIG_FILE}")
        print(f"Logs: {LOG_FILE}")
        print(f"Signal checker: {signal_checker}")
        print(f"Example integration: {example_script}")
        return 0
    
    logging.info(f"Starting Smart Requirements Updater v{VERSION}")
    
    # Always check for own dependency updates (but don't update without flag)
    for package_name, info in SCRIPT_DEPENDENCIES.items():
        if info["required"] and not is_package_installed(package_name) and not info["replacements"]:
            logging.warning(f"Required dependency {package_name} is missing. Run with --update-self to install it.")
        
        if is_package_installed(package_name) and info["replacements"]:
            logging.warning(f"Obsolete dependency {package_name} is installed. Run with --update-self to replace it with {', '.join(info['replacements'])}.")
    
    # Print system info
    print_system_info()
    
    # Create startup signal
    create_signal("updater_started")
    
    # Clean up old signals
    cleanup_old_signals()
    
    # Load configuration
    config = load_config()
    
    # Update knowledge base
    update_knowledge_base_from_web()
    
    # Step 1: Update conda if enabled
    if config.get("update_conda", True):
        update_conda_environments()
    
    # Step 2-4: Find, backup, and update projects
    projects = find_python_projects(config)
    
    projects_updated = 0
    projects_processed = 0
    
    for project_dir in projects:
        projects_processed += 1
        
        if args.dry_run:
            logging.info(f"Dry run - would process {project_dir}")
        else:
            if process_python_project(project_dir, config):
                projects_updated += 1
    
    logging.info(f"Completed processing {projects_processed} Python projects")
    logging.info(f"Updated {projects_updated} projects")
    
    # Generate helper scripts
    generate_signal_checker()
    generate_example_script()
    
    # Create a completion signal
    create_signal("updater_completed")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
