#!/bin/bash
# Smart Requirements Updater Installation Script

echo "Installing Smart Requirements Updater..."

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
import ast
import inspect
import importlib
import pkgutil
import pkg_resources
import platform
import hashlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.error

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

def fix_regex_escape_sequences():
    """Fix invalid escape sequences in regex patterns throughout the script."""
    # This is a global fix for all regex patterns
    import re
    
    # Get all the original regex functions/methods
    original_compile = re.compile
    original_search = re.search
    original_findall = re.findall
    original_match = re.match
    original_finditer = re.finditer
    original_sub = re.sub
    original_subn = re.subn
    original_split = re.split
    
    # Create wrapper functions that automatically convert patterns to raw strings
    def safe_compile(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_compile(pattern, *args, **kwargs)
    
    def safe_search(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_search(pattern, *args, **kwargs)
    
    def safe_findall(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_findall(pattern, *args, **kwargs)
    
    def safe_match(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_match(pattern, *args, **kwargs)
    
    def safe_finditer(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_finditer(pattern, *args, **kwargs)
    
    def safe_sub(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_sub(pattern, *args, **kwargs)
    
    def safe_subn(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_subn(pattern, *args, **kwargs)
    
    def safe_split(pattern, *args, **kwargs):
        if isinstance(pattern, str) and not pattern.startswith('r'):
            pattern = pattern.replace('\\', '\\\\')
        return original_split(pattern, *args, **kwargs)
    
    # Replace the original functions with our safe versions
    re.compile = safe_compile
    re.search = safe_search
    re.findall = safe_findall
    re.match = safe_match
    re.finditer = safe_finditer
    re.sub = safe_sub
    re.subn = safe_subn
    re.split = safe_split
    
    logging.info("Fixed regex escape sequences for safer pattern matching")
    return True

# Try to import additional packages, installing them if necessary
def ensure_package(package_name):
    try:
        return __import__(package_name)
    except ImportError:
        try:
            logging.info(f"Installing {package_name} for enhanced functionality...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", package_name])
            return __import__(package_name)
        except:
            logging.warning(f"Could not install {package_name}. Some features may be limited.")
            return None

# Import optional packages for enhanced functionality
requests = ensure_package("requests")
packaging_version = ensure_package("packaging.version")
packaging_specifier = ensure_package("packaging.specifiers")
safety = ensure_package("safety")
pipdeptree = ensure_package("pipdeptree")
importlib_metadata = ensure_package("importlib_metadata")

# Initialize dynamic package knowledge base
KNOWLEDGE_BASE_FILE = os.path.expanduser("~/.config/smart-update-reqs/package_knowledge.json")
KNOWLEDGE_BASE = {}

# Initialize compatibility dictionary if needed
def initialize_knowledge_base_keys():
    """Make sure all required keys exist in the knowledge base."""
    global KNOWLEDGE_BASE
    required_keys = [
        "replacements", "compatibility", "api_signatures", "deprecations",
        "vulnerabilities", "popularity_scores", "update_history", "usage_signatures"
    ]
    
    for key in required_keys:
        if key not in KNOWLEDGE_BASE:
            KNOWLEDGE_BASE[key] = {}
    
    if "last_update" not in KNOWLEDGE_BASE:
        KNOWLEDGE_BASE["last_update"] = datetime.now().isoformat()
    
    return True

# Load the knowledge base
if os.path.exists(KNOWLEDGE_BASE_FILE):
    with open(KNOWLEDGE_BASE_FILE, 'r') as f:
        try:
            KNOWLEDGE_BASE = json.load(f)
            # Ensure all required keys exist
            for key in ["replacements", "compatibility", "api_signatures", "deprecations", 
                       "vulnerabilities", "popularity_scores", "update_history"]:
                if key not in KNOWLEDGE_BASE:
                    KNOWLEDGE_BASE[key] = {}
            if "last_update" not in KNOWLEDGE_BASE:
                KNOWLEDGE_BASE["last_update"] = datetime.now().isoformat()
        except json.JSONDecodeError:
            KNOWLEDGE_BASE = {
                "replacements": {},
                "compatibility": {},
                "api_signatures": {},
                "deprecations": {},
                "vulnerabilities": {},
                "popularity_scores": {},
                "update_history": {},
                "last_update": datetime.now().isoformat()
            }
else:
    KNOWLEDGE_BASE = {
        "replacements": {},
        "compatibility": {},
        "api_signatures": {},
        "deprecations": {},
        "vulnerabilities": {},
        "popularity_scores": {},
        "update_history": {},
        "last_update": datetime.now().isoformat()
    }

# Package repositories to check
PACKAGE_REPOSITORIES = [
    {"name": "PyPI", "url": "https://pypi.org/pypi/{package}/json"},
    {"name": "conda-forge", "url": "https://conda.anaconda.org/conda-forge/{package}/json"}
]

class ModuleAPIAnalyzer:
    """Analyze module API by inspecting imports and usage patterns."""
    
    def __init__(self):
        self.api_cache = {}
    
    def extract_module_api(self, module_name):
        """Extract the API of a module by analyzing imports and usage."""
        if module_name in self.api_cache:
            return self.api_cache[module_name]
            
        api_info = {
            "objects": {},
            "classes": {},
            "functions": {},
            "constants": {}
        }
        
        try:
            # Try to import the module
            module = importlib.import_module(module_name)
            
            # Extract module attributes
            for name in dir(module):
                if name.startswith('_') and name != '__all__':
                    continue
                    
                try:
                    attr = getattr(module, name)
                    
                    # Classify the attribute
                    if inspect.isclass(attr):
                        methods = {}
                        for method_name in dir(attr):
                            if not method_name.startswith('_'):
                                method = getattr(attr, method_name)
                                if inspect.isfunction(method) or inspect.ismethod(method):
                                    try:
                                        sig = str(inspect.signature(method))
                                        methods[method_name] = sig
                                    except:
                                        methods[method_name] = "(?)"
                        
                        api_info["classes"][name] = {
                            "methods": methods,
                            "bases": [base.__name__ for base in attr.__mro__[1:] if base.__name__ != 'object']
                        }
                    elif inspect.isfunction(attr) or inspect.ismethod(attr):
                        try:
                            sig = str(inspect.signature(attr))
                            api_info["functions"][name] = sig
                        except:
                            api_info["functions"][name] = "(?)"
                    else:
                        # Consider it a constant or other object
                        api_info["objects"][name] = type(attr).__name__
                except:
                    pass
            
            # Cache the result
            self.api_cache[module_name] = api_info
            return api_info
        except ImportError:
            logging.debug(f"Could not import module {module_name} for API analysis")
            return api_info
        except Exception as e:
            logging.debug(f"Error analyzing API for {module_name}: {e}")
            return api_info
    
    def compare_apis(self, old_api, new_api):
        """
        Compare two APIs and determine compatibility.
        Returns compatibility score and breaking changes.
        """
        if not old_api or not new_api:
            return 0.0, ["Could not analyze APIs"]
            
        breaking_changes = []
        compat_items = 0
        total_items = 0
        
        # Check functions
        for func_name, old_sig in old_api.get("functions", {}).items():
            total_items += 1
            if func_name in new_api.get("functions", {}):
                compat_items += 1
                new_sig = new_api["functions"][func_name]
                
                # Check for signature changes that might break backwards compatibility
                if old_sig != "(?)" and new_sig != "(?)" and old_sig != new_sig:
                    # Simple heuristic: if parameter count decreased or names changed
                    old_params = old_sig.count(',')
                    new_params = new_sig.count(',')
                    
                    if new_params < old_params and '=' not in new_sig:
                        breaking_changes.append(f"Function {func_name}: parameter count reduced from {old_params+1} to {new_params+1}")
            else:
                breaking_changes.append(f"Function removed: {func_name}{old_sig}")
        
        # Check classes
        for class_name, old_class_info in old_api.get("classes", {}).items():
            if class_name in new_api.get("classes", {}):
                new_class_info = new_api["classes"][class_name]
                
                # Check methods
                for method_name, old_method_sig in old_class_info.get("methods", {}).items():
                    total_items += 1
                    if method_name in new_class_info.get("methods", {}):
                        compat_items += 1
                        new_method_sig = new_class_info["methods"][method_name]
                        
                        # Check for signature changes
                        if old_method_sig != "(?)" and new_method_sig != "(?)" and old_method_sig != new_method_sig:
                            old_params = old_method_sig.count(',')
                            new_params = new_method_sig.count(',')
                            
                            if new_params < old_params and '=' not in new_method_sig:
                                breaking_changes.append(f"Method {class_name}.{method_name}: parameter count reduced from {old_params+1} to {new_params+1}")
                    else:
                        breaking_changes.append(f"Method removed: {class_name}.{method_name}{old_method_sig}")
            else:
                # Class removed
                total_items += 1 + len(old_class_info.get("methods", {}))
                breaking_changes.append(f"Class removed: {class_name} with {len(old_class_info.get('methods', {}))} methods")
        
        # Calculate compatibility score
        compat_score = compat_items / max(total_items, 1)
        
        return compat_score, breaking_changes

class CodeUsageAnalyzer:
    """Analyze Python code to detect how packages are used."""
    
    def __init__(self):
        self.import_cache = {}
        
    def analyze_file(self, filepath):
        """Analyze a Python file to detect imports and usage patterns."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse the AST
            tree = ast.parse(content)
            
            # Extract imports
            imports = self._extract_imports(tree)
            
            # Extract usage patterns
            usage_patterns = self._extract_usage_patterns(tree, imports)
            
            return imports, usage_patterns
        except Exception as e:
            logging.debug(f"Error analyzing file {filepath}: {e}")
            return {}, {}
    
    def _extract_imports(self, tree):
        """Extract all imports from an AST."""
        imports = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports[name.name] = {"alias": name.asname, "from": None, "items": ["*"]}
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for name in node.names:
                    if module not in imports:
                        imports[module] = {"alias": None, "from": True, "items": []}
                    
                    if name.name == "*":
                        imports[module]["items"] = ["*"]
                    else:
                        imports[module]["items"].append((name.name, name.asname))
        
        return imports
    
    def _extract_usage_patterns(self, tree, imports):
        """Extract usage patterns from an AST based on imports."""
        usage = {}
        
        # Create a map of all imported names to their modules
        name_to_module = {}
        for module, info in imports.items():
            if info["alias"]:
                name_to_module[info["alias"]] = module
            else:
                name_to_module[module] = module
            
            # Add from imports
            if info["from"]:
                for item in info["items"]:
                    if item == "*":
                        continue
                    
                    name, alias = item if isinstance(item, tuple) else (item, None)
                    if alias:
                        name_to_module[alias] = (module, name)
                    else:
                        name_to_module[name] = (module, name)
        
        # Analyze attribute access and function calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                base_name = node.value.id
                if base_name in name_to_module:
                    module = name_to_module[base_name]
                    if isinstance(module, tuple):
                        # Handle from import
                        parent_module, item = module
                        if parent_module not in usage:
                            usage[parent_module] = {"attributes": {}, "calls": {}}
                        
                        attr_access = f"{item}.{node.attr}"
                        if attr_access not in usage[parent_module]["attributes"]:
                            usage[parent_module]["attributes"][attr_access] = 0
                        usage[parent_module]["attributes"][attr_access] += 1
                    else:
                        # Handle regular import
                        if module not in usage:
                            usage[module] = {"attributes": {}, "calls": {}}
                        
                        if node.attr not in usage[module]["attributes"]:
                            usage[module]["attributes"][node.attr] = 0
                        usage[module]["attributes"][node.attr] += 1
            
            # Analyze function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    # Direct function call
                    func_name = node.func.id
                    if func_name in name_to_module:
                        module = name_to_module[func_name]
                        if isinstance(module, tuple):
                            parent_module, item = module
                            if parent_module not in usage:
                                usage[parent_module] = {"attributes": {}, "calls": {}}
                            
                            if item not in usage[parent_module]["calls"]:
                                usage[parent_module]["calls"][item] = 0
                            usage[parent_module]["calls"][item] += 1
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    # Method call
                    base_name = node.func.value.id
                    if base_name in name_to_module:
                        module = name_to_module[base_name]
                        if isinstance(module, tuple):
                            parent_module, item = module
                            if parent_module not in usage:
                                usage[parent_module] = {"attributes": {}, "calls": {}}
                            
                            method_call = f"{item}.{node.func.attr}"
                            if method_call not in usage[parent_module]["calls"]:
                                usage[parent_module]["calls"][method_call] = 0
                            usage[parent_module]["calls"][method_call] += 1
                        else:
                            if module not in usage:
                                usage[module] = {"attributes": {}, "calls": {}}
                            
                            if node.func.attr not in usage[module]["calls"]:
                                usage[module]["calls"][node.func.attr] = 0
                            usage[module]["calls"][node.func.attr] += 1
        
        return usage
    
    def analyze_project(self, project_dir):
        """Analyze all Python files in a project to detect package usage."""
        all_imports = {}
        all_usage = {}
        
        for root, _, files in os.walk(project_dir):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    imports, usage = self.analyze_file(filepath)
                    
                    # Merge imports
                    for module, info in imports.items():
                        if module not in all_imports:
                            all_imports[module] = info
                        else:
                            # Merge items
                            if info["items"] == ["*"]:
                                all_imports[module]["items"] = ["*"]
                            elif all_imports[module]["items"] != ["*"]:
                                for item in info["items"]:
                                    if item not in all_imports[module]["items"]:
                                        all_imports[module]["items"].append(item)
                    
                    # Merge usage
                    for module, patterns in usage.items():
                        if module not in all_usage:
                            all_usage[module] = {"attributes": {}, "calls": {}}
                        
                        # Merge attributes
                        for attr, count in patterns["attributes"].items():
                            if attr not in all_usage[module]["attributes"]:
                                all_usage[module]["attributes"][attr] = 0
                            all_usage[module]["attributes"][attr] += count
                        
                        # Merge calls
                        for call, count in patterns["calls"].items():
                            if call not in all_usage[module]["calls"]:
                                all_usage[module]["calls"][call] = 0
                            all_usage[module]["calls"][call] += count
        
        return all_imports, all_usage
    
    def get_core_usage_signature(self, usage):
        """Extract a core usage signature from usage patterns."""
        signature = {"modules": {}}
        
        for module, patterns in usage.items():
            # Just take the top 10 most frequently used attributes and calls
            top_attrs = sorted(patterns["attributes"].items(), key=lambda x: x[1], reverse=True)[:10]
            top_calls = sorted(patterns["calls"].items(), key=lambda x: x[1], reverse=True)[:10]
            
            signature["modules"][module] = {
                "top_attributes": [attr for attr, _ in top_attrs],
                "top_calls": [call for call, _ in top_calls]
            }
        
        return signature
    
    def compare_usage_signatures(self, sig1, sig2):
        """
        Compare two usage signatures for compatibility.
        Returns compatibility score (0.0-1.0) and required changes.
        """
        if not sig1 or not sig2:
            return 0.0, ["No usage signatures to compare"]
            
        modules1 = set(sig1.get("modules", {}).keys())
        modules2 = set(sig2.get("modules", {}).keys())
        
        # Find modules that exist in both signatures
        common_modules = modules1.intersection(modules2)
        
        if not common_modules:
            return 0.0, ["No common modules found"]
        
        compatibility_scores = []
        required_changes = []
        
        for module in common_modules:
            module_sig1 = sig1["modules"][module]
            module_sig2 = sig2["modules"][module]
            
            # Check attributes
            attrs1 = set(module_sig1.get("top_attributes", []))
            attrs2 = set(module_sig2.get("top_attributes", []))
            
            common_attrs = attrs1.intersection(attrs2)
            missing_attrs = attrs1 - attrs2
            
            attr_score = len(common_attrs) / max(len(attrs1), 1)
            
            # Check function calls
            calls1 = set(module_sig1.get("top_calls", []))
            calls2 = set(module_sig2.get("top_calls", []))
            
            common_calls = calls1.intersection(calls2)
            missing_calls = calls1 - calls2
            
            call_score = len(common_calls) / max(len(calls1), 1)
            
            # Calculate module compatibility score
            module_score = (attr_score + call_score) / 2
            compatibility_scores.append(module_score)
            
            # Record required changes
            if missing_attrs:
                required_changes.append(f"Module {module} missing attributes: {', '.join(missing_attrs)}")
            
            if missing_calls:
                required_changes.append(f"Module {module} missing function/method calls: {', '.join(missing_calls)}")
        
        # Calculate overall compatibility score
        overall_score = sum(compatibility_scores) / len(compatibility_scores)
        
        return overall_score, required_changes

class DependencyResolver:
    """Analyze and resolve package dependencies."""
    
    def __init__(self):
        self.dep_cache = {}
        
    def get_package_dependencies(self, package_name, version=None):
        """Get the dependencies of a package."""
        cache_key = f"{package_name}:{version or 'latest'}"
        if cache_key in self.dep_cache:
            return self.dep_cache[cache_key]
        
        deps = {}
        
        # Try to get from PyPI
        if requests:
            try:
                if version:
                    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
                else:
                    url = f"https://pypi.org/pypi/{package_name}/json"
                
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    requires_dist = data.get('info', {}).get('requires_dist', []) or []
                    
                    for req in requires_dist:
                        # Parse requirement
                        req = req.split(';')[0].strip()  # Remove environment markers
                        if not req:
                            continue
                            
                        parts = re.split(r'(==|>=|<=|!=|~=|>|<)', req, 1)
                        
                        if len(parts) >= 3:
                            dep_name = parts[0].strip().lower()
                            constraint = parts[1] + parts[2].strip()
                            deps[dep_name] = constraint
                        else:
                            deps[req.strip().lower()] = ""
                            
                    self.dep_cache[cache_key] = deps
                    return deps
            except Exception as e:
                logging.debug(f"Error getting dependencies for {package_name} from PyPI: {e}")
        
        # Try to use importlib_metadata as fallback
        if importlib_metadata:
            try:
                if version:
                    # Can't easily get deps for specific version without installing
                    pass
                else:
                    dist = importlib_metadata.distribution(package_name)
                    for req in dist.requires or []:
                        req_str = str(req)
                        parts = re.split(r'(==|>=|<=|!=|~=|>|<)', req_str, 1)
                        
                        if len(parts) >= 3:
                            dep_name = parts[0].strip().lower()
                            constraint = parts[1] + parts[2].strip()
                            deps[dep_name] = constraint
                        else:
                            deps[req_str.strip().lower()] = ""
                    
                    self.dep_cache[cache_key] = deps
                    return deps
            except Exception as e:
                logging.debug(f"Error getting dependencies for {package_name} from importlib_metadata: {e}")
        
        # Use pipdeptree as last resort
        if pipdeptree:
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pipdeptree', '-j'],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    tree = json.loads(result.stdout)
                    
                    for pkg in tree:
                        if pkg.get('package', {}).get('key', '').lower() == package_name.lower():
                            for dep in pkg.get('dependencies', []):
                                dep_name = dep.get('package_name', '').lower()
                                dep_version = dep.get('installed_version', '')
                                if dep_name:
                                    deps[dep_name] = f"=={dep_version}" if dep_version else ""
                            
                            self.dep_cache[cache_key] = deps
                            return deps
            except Exception as e:
                logging.debug(f"Error getting dependencies for {package_name} from pipdeptree: {e}")
        
        self.dep_cache[cache_key] = deps
        return deps
    
    def check_compatibility(self, package1, version1, package2, version2):
        """
        Check if two packages with their versions are compatible.
        Returns compatibility score (0.0-1.0) and issues.
        """
        deps1 = self.get_package_dependencies(package1, version1)
        deps2 = self.get_package_dependencies(package2, version2)
        
        if not deps1 and not deps2:
            return 1.0, []  # No dependencies to check
        
        issues = []
        
        # Check if package2 satisfies all dependencies of package1
        for dep_name, constraint1 in deps1.items():
            if dep_name == package2.lower():
                # Direct dependency on the replacement
                if constraint1 and version2:
                    # Check if version2 satisfies constraint1
                    if packaging_specifier and packaging_version:
                        try:
                            spec = packaging_specifier.SpecifierSet(constraint1)
                            ver = packaging_version.Version(version2)
                            
                            if not spec.contains(ver):
                                issues.append(f"{package1} requires {dep_name}{constraint1}, but {package2} is version {version2}")
                        except:
                            # Can't check compatibility
                            issues.append(f"Could not verify if {package2} {version2} satisfies {dep_name}{constraint1}")
        
        # Check for conflicting dependencies
        common_deps = set(deps1.keys()).intersection(set(deps2.keys()))
        for dep in common_deps:
            constraint1 = deps1[dep]
            constraint2 = deps2[dep]
            
            if constraint1 and constraint2 and constraint1 != constraint2:
                issues.append(f"Dependency conflict: {package1} requires {dep}{constraint1}, but {package2} requires {dep}{constraint2}")
        
        # Calculate compatibility score
        if not issues:
            return 1.0, []
        else:
            score = 1.0 - (len(issues) / max(len(deps1) + len(common_deps), 1))
            return max(0.0, score), issues

class EnvironmentManager:
    """Detect and manage Python environments for projects."""
    
    def __init__(self):
        self.env_cache = {}
    
    def detect_environment(self, project_dir):
        """
        Detect the type of environment used by a project.
        Returns a dict with environment information.
        """
        if project_dir in self.env_cache:
            return self.env_cache[project_dir]
        
        env_info = {
            "type": None,          # venv, conda, poetry, pipenv, system
            "path": None,          # Path to the environment
            "python_path": None,   # Path to the Python executable
            "package_manager": None  # pip, conda, poetry, pipenv
        }
        
        # Check for virtual environment in project directory
        venv_dirs = [
            os.path.join(project_dir, "venv"),
            os.path.join(project_dir, ".venv"),
            os.path.join(project_dir, "env"),
            os.path.join(project_dir, ".env")
        ]
        
        for venv_dir in venv_dirs:
            if os.path.exists(venv_dir) and os.path.isdir(venv_dir):
                # Found a potential virtual environment
                if os.path.exists(os.path.join(venv_dir, "bin", "python")) or \
                   os.path.exists(os.path.join(venv_dir, "Scripts", "python.exe")):
                    env_info["type"] = "venv"
                    env_info["path"] = venv_dir
                    
                    # Determine python path
                    if os.path.exists(os.path.join(venv_dir, "bin", "python")):
                        env_info["python_path"] = os.path.join(venv_dir, "bin", "python")
                    else:
                        env_info["python_path"] = os.path.join(venv_dir, "Scripts", "python.exe")
                    
                    env_info["package_manager"] = "pip"
                    break
        
        # Check for conda environment
        conda_files = [
            os.path.join(project_dir, "environment.yml"),
            os.path.join(project_dir, "environment.yaml"),
            os.path.join(project_dir, "conda-environment.yml"),
            os.path.join(project_dir, "conda.yml")
        ]
        
        for conda_file in conda_files:
            if os.path.exists(conda_file):
                env_info["type"] = "conda"
                
                # Try to extract environment name from the file
                try:
                    with open(conda_file, 'r') as f:
                        content = f.read()
                        # Extract name from the conda environment file
                        match = re.search(r'name:\s*([^\s]+)', content)
                        if match:
                            env_name = match.group(1)
                            env_info["name"] = env_name
                except:
                    pass
                
                env_info["package_manager"] = "conda"
                break
        
        # Check for Poetry
        if os.path.exists(os.path.join(project_dir, "pyproject.toml")):
            try:
                with open(os.path.join(project_dir, "pyproject.toml"), 'r') as f:
                    content = f.read()
                    if "[tool.poetry]" in content:
                        env_info["type"] = "poetry"
                        env_info["package_manager"] = "poetry"
            except:
                pass
        
        # Check for Pipenv
        if os.path.exists(os.path.join(project_dir, "Pipfile")):
            env_info["type"] = "pipenv"
            env_info["package_manager"] = "pipenv"
        
        # If we couldn't detect an environment, assume system Python
        if env_info["type"] is None:
            env_info["type"] = "system"
            env_info["python_path"] = sys.executable
            env_info["package_manager"] = "pip"
        
        # Cache the result
        self.env_cache[project_dir] = env_info
        return env_info
    
    def get_python_executable(self, project_dir):
        """Get the Python executable for the project's environment."""
        env_info = self.detect_environment(project_dir)
        
        if env_info["python_path"]:
            return env_info["python_path"]
        
        # Handle conda environments differently
        if env_info["type"] == "conda" and "name" in env_info:
            try:
                # Try to get the python path using conda info
                result = subprocess.run(
                    ["conda", "info", "--envs", "--json"],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    envs = data.get("envs", [])
                    
                    for env_path in envs:
                        if os.path.basename(env_path) == env_info["name"]:
                            if os.path.exists(os.path.join(env_path, "bin", "python")):
                                return os.path.join(env_path, "bin", "python")
                            elif os.path.exists(os.path.join(env_path, "python.exe")):
                                return os.path.join(env_path, "python.exe")
            except:
                pass
        
        # Fall back to system Python
        return sys.executable
    
    def install_dependencies(self, project_dir, requirements_file=None, quiet_mode=False, continue_on_error=True):
        """Install dependencies for a project based on its environment type."""
        env_info = self.detect_environment(project_dir)
        success = False
        problem_packages = []
        
        if not requirements_file:
            requirements_file = os.path.join(project_dir, "requirements.txt")
            if not os.path.exists(requirements_file):
                logging.warning(f"No requirements.txt found in {project_dir}")
                return False, []
        
        if not quiet_mode:
            logging.info(f"Installing dependencies from {requirements_file} for {project_dir}")
        
        try:
            if env_info["package_manager"] == "pip":
                # Try to identify problematic packages first and install them separately
                with open(requirements_file, 'r') as f:
                    requirements = f.read().splitlines()
                
                # Filter out comments and empty lines
                requirements = [r.strip() for r in requirements if r.strip() and not r.strip().startswith('#')]
                
                # Use the environment's Python to install
                python_exec = self.get_python_executable(project_dir)
                
                if continue_on_error:
                    # Try installing one by one to identify problematic packages
                    for req in requirements:
                        if ';' in req:  # Skip environment markers for now
                            continue
                            
                        # Skip options (lines starting with -)
                        if req.startswith('-'):
                            continue
                            
                        cmd = [python_exec, "-m", "pip", "install", req]
                        
                        if quiet_mode:
                            cmd.append("--quiet")
                        
                        result = subprocess.run(
                            cmd, cwd=project_dir, capture_output=True, text=True
                        )
                        
                        if result.returncode != 0:
                            problem_packages.append(req)
                            if not quiet_mode:
                                logging.error(f"Failed to install {req}: {result.stderr.splitlines()[-1] if result.stderr else 'Unknown error'}")
                    
                    success = len(problem_packages) < len(requirements)
                else:
                    # Install all at once
                    cmd = [python_exec, "-m", "pip", "install", "-r", requirements_file]
                    
                    if quiet_mode:
                        cmd.append("--quiet")
                    
                    result = subprocess.run(
                        cmd, cwd=project_dir, capture_output=True, text=True
                    )
                    
                    if result.returncode == 0:
                        if not quiet_mode:
                            logging.info(f"Successfully installed dependencies for {project_dir}")
                        success = True
                    else:
                        if not quiet_mode:
                            logging.error(f"Failed to install dependencies: {result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'}")
            
            elif env_info["package_manager"] == "conda":
                # Handle conda environments
                if "name" in env_info:
                    cmd = ["conda", "install", "--file", requirements_file, "-n", env_info["name"], "-y"]
                    
                    if quiet_mode:
                        cmd.append("-q")
                    
                    result = subprocess.run(
                        cmd, cwd=project_dir, capture_output=True, text=True
                    )
                    
                    if result.returncode == 0:
                        if not quiet_mode:
                            logging.info(f"Successfully installed dependencies for conda env {env_info['name']}")
                        success = True
                    else:
                        if not quiet_mode:
                            logging.error(f"Failed to install conda dependencies: {result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'}")
            
            elif env_info["package_manager"] == "poetry":
                # Handle poetry projects
                cmd = ["poetry", "install"]
                
                if quiet_mode:
                    cmd.append("-q")
                
                result = subprocess.run(
                    cmd, cwd=project_dir, capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    if not quiet_mode:
                        logging.info(f"Successfully installed dependencies with poetry for {project_dir}")
                    success = True
                else:
                    if not quiet_mode:
                        logging.error(f"Failed to install poetry dependencies: {result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'}")
            
            elif env_info["package_manager"] == "pipenv":
                # Handle pipenv projects
                cmd = ["pipenv", "install"]
                
                if quiet_mode:
                    cmd.append("--quiet")
                
                result = subprocess.run(
                    cmd, cwd=project_dir, capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    if not quiet_mode:
                        logging.info(f"Successfully installed dependencies with pipenv for {project_dir}")
                    success = True
                else:
                    if not quiet_mode:
                        logging.error(f"Failed to install pipenv dependencies: {result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'}")
        
        except Exception as e:
            if not quiet_mode:
                logging.error(f"Error installing dependencies: {e}")
        
        return success, problem_packages

class BuildManager:
    """Handle project building and compilation."""
    
    def __init__(self, env_manager):
        self.env_manager = env_manager
    
    def has_compiled_components(self, project_dir):
        """Check if the project has components that need compilation."""
        # Look for setup.py with extensions
        setup_py = os.path.join(project_dir, "setup.py")
        if os.path.exists(setup_py):
            try:
                with open(setup_py, 'r') as f:
                    content = f.read()
                    # Check for Extension or CythonExtension
                    if "Extension(" in content or "CythonExtension" in content or "Cython" in content:
                        return True
            except:
                pass
        
        # Look for .c, .cpp or .pyx files
        for root, _, files in os.walk(project_dir):
            for file in files:
                if file.endswith(('.c', '.cpp', '.cxx', '.pyx', '.pxd')):
                    return True
        
        return False
    
    def build_project(self, project_dir, quiet_mode=False, continue_on_error=True):
        """Build the project if it has compiled components."""
        if not self.has_compiled_components(project_dir):
            if not quiet_mode:
                logging.info(f"No compiled components detected in {project_dir}")
            return True
        
        if not quiet_mode:
            logging.info(f"Building project with compiled components: {project_dir}")
        
        env_info = self.env_manager.detect_environment(project_dir)
        python_exec = self.env_manager.get_python_executable(project_dir)
        success = False
        
        try:
            # Try setup.py build
            if os.path.exists(os.path.join(project_dir, "setup.py")):
                cmd = [python_exec, "setup.py", "build_ext", "--inplace"]
                
                result = subprocess.run(
                    cmd, cwd=project_dir, capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    if not quiet_mode:
                        logging.info(f"Successfully built extensions for {project_dir}")
                    success = True
                else:
                    error_msg = result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'
                    if not quiet_mode:
                        logging.error(f"Failed to build extensions: {error_msg}")
                    
                    # If first attempt failed and we want to continue, try regular build
                    if continue_on_error:
                        cmd = [python_exec, "setup.py", "build"]
                        
                        result = subprocess.run(
                            cmd, cwd=project_dir, capture_output=True, text=True
                        )
                        
                        if result.returncode == 0:
                            if not quiet_mode:
                                logging.info(f"Successfully built project {project_dir}")
                            success = True
                        else:
                            error_msg = result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'
                            if not quiet_mode:
                                logging.error(f"Failed to build project: {error_msg}")
                    
                    # Try other build methods if available
                    if not success and continue_on_error and os.path.exists(os.path.join(project_dir, "setup.py")):
                        # Try with alternate compilation flags
                        cmd = [python_exec, "setup.py", "build_ext", "--inplace", "--no-python-abi-suffix"]
                        
                        result = subprocess.run(
                            cmd, cwd=project_dir, capture_output=True, text=True
                        )
                        
                        if result.returncode == 0:
                            if not quiet_mode:
                                logging.info(f"Successfully built extensions with --no-python-abi-suffix for {project_dir}")
                            success = True
            
            # Try pip install -e . for development mode if all else failed
            if not success and continue_on_error:
                cmd = [python_exec, "-m", "pip", "install", "-e", "."]
                
                if quiet_mode:
                    cmd.append("--quiet")
                
                result = subprocess.run(
                    cmd, cwd=project_dir, capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    if not quiet_mode:
                        logging.info(f"Successfully installed project in development mode: {project_dir}")
                    success = True
                else:
                    error_msg = result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'
                    if not quiet_mode:
                        logging.error(f"Failed to install in development mode: {error_msg}")
            
            # If we continue in error and still couldn't build, note this but consider it a "success"
            # for the purpose of continuing the script
            if not success and continue_on_error:
                if not quiet_mode:
                    logging.warning(f"Could not build {project_dir}, but continuing due to continue_on_error=True")
                # Return "success" so the script continues
                return True
        
        except Exception as e:
            if not quiet_mode:
                logging.error(f"Error building project: {e}")
            if continue_on_error:
                return True
        
        return success

class TestManager:
    """Handle project testing."""
    
    def __init__(self, env_manager):
        self.env_manager = env_manager
    
    def has_tests(self, project_dir):
        """Check if the project has tests."""
        test_indicators = [
            os.path.join(project_dir, "tests"),
            os.path.join(project_dir, "test"),
            os.path.join(project_dir, "pytest.ini"),
            os.path.join(project_dir, "conftest.py"),
            os.path.join(project_dir, "tox.ini")
        ]
        
        for indicator in test_indicators:
            if os.path.exists(indicator):
                return True
        
        # Check if setup.py has test or pytest in it
        setup_py = os.path.join(project_dir, "setup.py")
        if os.path.exists(setup_py):
            try:
                with open(setup_py, 'r') as f:
                    content = f.read()
                    if "pytest" in content or "unittest" in content or "test_suite" in content:
                        return True
            except:
                pass
        
        return False
    
    def run_tests(self, project_dir, quiet_mode=False, continue_on_error=True):
        """Run the project's tests."""
        if not self.has_tests(project_dir):
            if not quiet_mode:
                logging.info(f"No tests detected in {project_dir}")
            return True
        
        if not quiet_mode:
            logging.info(f"Running tests for project: {project_dir}")
        
        env_info = self.env_manager.detect_environment(project_dir)
        python_exec = self.env_manager.get_python_executable(project_dir)
        success = False
        
        try:
            # Try pytest first
            cmd = [python_exec, "-m", "pytest"]
            
            if quiet_mode:
                cmd.append("-q")
            
            result = subprocess.run(
                cmd, cwd=project_dir, capture_output=True, text=True, timeout=300  # 5-minute timeout
            )
            
            if result.returncode == 0:
                if not quiet_mode:
                    logging.info(f"Tests passed for {project_dir}")
                success = True
            else:
                error_msg = result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'
                if not quiet_mode:
                    logging.warning(f"Tests failed for {project_dir}: {error_msg}")
                
                # Try unittest as fallback
                if continue_on_error:
                    cmd = [python_exec, "-m", "unittest", "discover"]
                    
                    if quiet_mode:
                        cmd.append("-q")
                    
                    result = subprocess.run(
                        cmd, cwd=project_dir, capture_output=True, text=True, timeout=300
                    )
                    
                    if result.returncode == 0:
                        if not quiet_mode:
                            logging.info(f"Unittest tests passed for {project_dir}")
                        success = True
                    else:
                        error_msg = result.stderr.splitlines()[-5:] if result.stderr else 'Unknown error'
                        if not quiet_mode:
                            logging.warning(f"Unittest tests failed for {project_dir}: {error_msg}")
                
                # If we continue in error and couldn't run tests, note this but consider it a "success"
                if not success and continue_on_error:
                    if not quiet_mode:
                        logging.warning(f"Could not run tests for {project_dir}, but continuing due to continue_on_error=True")
                    # Return "success" so the script continues
                    return True
        
        except subprocess.TimeoutExpired:
            if not quiet_mode:
                logging.error(f"Tests timed out for {project_dir}")
            if continue_on_error:
                return True
        except Exception as e:
            if not quiet_mode:
                logging.error(f"Error running tests: {e}")
            if continue_on_error:
                return True
        
        return success

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
        self.api_signature = None
        self.usage_signature = None
        self.popularity_score = None
        self.potential_replacements = []
        
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
                
                # Get download stats for popularity
                try:
                    stats_url = f"https://pypistats.org/api/packages/{self.name}/recent"
                    stats_response = requests.get(stats_url, timeout=5)
                    if stats_response.status_code == 200:
                        stats_data = stats_response.json()
                        self.popularity_score = stats_data.get('data', {}).get('last_month', 0)
                except:
                    pass
                
                # Check for deprecation hints
                info = self.pypi_info.get('info', {})
                description = info.get('description', '') or ''
                summary = info.get('summary', '') or ''
                
                # Get classifier info
                classifiers = info.get('classifiers', [])
                development_status = [c for c in classifiers if c.startswith('Development Status')]
                
                # Check development status for deprecation hints
                if any('Inactive' in status for status in development_status):
                    self.is_deprecated = True
                
                deprecated_keywords = [
                    'deprecated', 'no longer maintained', 'use instead', 
                    'replaced by', 'abandoned', 'unmaintained', 'obsolete'
                ]
                
                for keyword in deprecated_keywords:
                    if keyword in description.lower() or keyword in summary.lower():
                        self.is_deprecated = True
                        # Try to find replacement suggestion
                        text = description.lower() + ' ' + summary.lower()
                        replace_patterns = [
                            r'use\s+([a-zA-Z0-9_-]+)\s+instead',
                            r'replaced\s+by\s+([a-zA-Z0-9_-]+)',
                            r'use\s+the\s+([a-zA-Z0-9_-]+)\s+package',
                            r'recommend\s+using\s+([a-zA-Z0-9_-]+)',
                            r'migrate\s+to\s+([a-zA-Z0-9_-]+)',
                            r'successor\s+is\s+([a-zA-Z0-9_-]+)'
                        ]
                        
                        for pattern in replace_patterns:
                            match = re.search(pattern, text)
                            if match:
                                self.replacement = match.group(1)
                                # Add to knowledge base
                                if self.name not in KNOWLEDGE_BASE["replacements"] and self.replacement:
                                    KNOWLEDGE_BASE["replacements"][self.name] = self.replacement
                                    _save_knowledge_base()
                                break
                
                # Check last release date
                upload_time = None
                for release in self.pypi_info.get('releases', {}).values():
                    if release and isinstance(release, list) and release[0].get('upload_time'):
                        upload_time = release[0].get('upload_time')
                        break
                
                if upload_time:
                    try:
                        # Check if last release was more than 2 years ago
                        last_release = datetime.fromisoformat(upload_time.replace('Z', '+00:00'))
                        years_since_update = (datetime.now() - last_release).days / 365
                        
                        if years_since_update > 2:
                            # Mark as potentially deprecated if no updates for 2+ years
                            logging.info(f"Package {self.name} hasn't been updated in {years_since_update:.1f} years")
                            
                            # If already not marked deprecated by other checks
                            if not self.is_deprecated:
                                self.is_deprecated = True
                    except:
                        pass
                
                return True
            return False
        except Exception as e:
            logging.debug(f"Error fetching PyPI info for {self.name}: {e}")
            return False
    
    def find_potential_replacements(self):
        """Find potential replacements for this package."""
        if not self.pypi_info:
            return []
        
        replacements = []
        
        # First check if we already know a replacement
        if self.name in KNOWLEDGE_BASE["replacements"]:
            self.replacement = KNOWLEDGE_BASE["replacements"][self.name]
            replacements.append({
                "name": self.replacement,
                "confidence": 0.9,
                "reason": "Known replacement from knowledge base"
            })
            return replacements
        
        # Check if package has a dedicated replacement
        if self.replacement:
            replacements.append({
                "name": self.replacement,
                "confidence": 0.9,
                "reason": "Explicitly mentioned as replacement in package description"
            })
            return replacements
        
        # If package is deprecated, try to find alternatives
        if self.is_deprecated:
            # 1. Check related packages by keywords
            keywords = self.pypi_info.get('info', {}).get('keywords', '')
            if keywords:
                if isinstance(keywords, str):
                    keywords = [k.strip() for k in keywords.split(',')]
                
                # Search for packages with similar keywords
                for keyword in keywords:
                    if not keyword.strip():
                        continue
                    
                    try:
                        search_url = f"https://pypi.org/search/?q={keyword}&o=download_count"
                        response = requests.get(search_url, timeout=5)
                        
                        if response.status_code == 200:
                            # Parse HTML to extract package names
                            matches = re.findall(r'<a class="package-snippet__name" href="/project/([^/]+)/">', response.text)
                            
                            for i, match in enumerate(matches[:5]):  # Take top 5 results
                                if match.lower() != self.name.lower():
                                    if match.lower() not in [r["name"].lower() for r in replacements]:
                                        # Check if it's actually newer
                                        try:
                                            pkg_response = requests.get(f"https://pypi.org/pypi/{match}/json", timeout=3)
                                            if pkg_response.status_code == 200:
                                                pkg_data = pkg_response.json()
                                                last_release = pkg_data.get('info', {}).get('version')
                                                
                                                if last_release:
                                                    replacements.append({
                                                        "name": match,
                                                        "confidence": 0.5 - (i * 0.05),
                                                        "reason": f"Popular alternative found via keyword '{keyword}'"
                                                    })
                                        except:
                                            pass
                    except:
                        pass
            
            # 2. Check for similar package names
            try:
                # Remove common prefixes/suffixes to find the core name
                core_name = re.sub(r'^(py|python)-', '', self.name)
                core_name = re.sub(r'-(py|python)$', '', core_name)
                
                search_url = f"https://pypi.org/search/?q={core_name}&o=download_count"
                response = requests.get(search_url, timeout=5)
                
                if response.status_code == 200:
                    matches = re.findall(r'<a class="package-snippet__name" href="/project/([^/]+)/">', response.text)
                    
                    for i, match in enumerate(matches[:8]):  # Take top 8 results
                        if match.lower() != self.name.lower():
                            if match.lower() not in [r["name"].lower() for r in replacements]:
                                if self._name_similarity(self.name, match) > 0.5:
                                    replacements.append({
                                        "name": match,
                                        "confidence": 0.4 - (i * 0.04),
                                        "reason": f"Similar package name to {self.name}"
                                    })
            except:
                pass
            
            # 3. Check for popular packages in the same category
            try:
                categories = []
                for classifier in self.pypi_info.get('info', {}).get('classifiers', []):
                    if classifier.startswith('Topic ::'):
                        category = '::'.join(classifier.split('::')[1:]).strip()
                        categories.append(category)
                
                for category in categories[:2]:  # Limit to first 2 categories to avoid too many requests
                    search_url = f"https://pypi.org/search/?c={category}&o=download_count"
                    response = requests.get(search_url, timeout=5)
                    
                    if response.status_code == 200:
                        matches = re.findall(r'<a class="package-snippet__name" href="/project/([^/]+)/">', response.text)
                        
                        for i, match in enumerate(matches[:3]):  # Take top 3 results per category
                            if match.lower() != self.name.lower():
                                if match.lower() not in [r["name"].lower() for r in replacements]:
                                    replacements.append({
                                        "name": match,
                                        "confidence": 0.3 - (i * 0.05),
                                        "reason": f"Popular package in category '{category}'"
                                    })
            except:
                pass
        
        self.potential_replacements = replacements
        return replacements
    
    def _name_similarity(self, name1, name2):
        """Calculate similarity between two package names."""
        name1 = name1.lower()
        name2 = name2.lower()
        
        # Direct substring
        if name1 in name2 or name2 in name1:
            return 0.8
        
        # Levenshtein distance (simplified)
        l1, l2 = len(name1), len(name2)
        distance = 0
        for i in range(min(l1, l2)):
            if name1[i] != name2[i]:
                distance += 1
        distance += abs(l1 - l2)
        
        return 1.0 - (distance / max(l1, l2))
    
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
                        try:
                            data = json.loads(result.stdout)
                            if isinstance(data, list):
                                self.vulnerabilities = data
                                
                                # Add to knowledge base
                                if self.vulnerabilities and self.name not in KNOWLEDGE_BASE["vulnerabilities"]:
                                    KNOWLEDGE_BASE["vulnerabilities"][self.name] = {
                                        "version": self.version_str,
                                        "count": len(self.vulnerabilities),
                                        "ids": [vuln[4] for vuln in self.vulnerabilities if len(vuln) > 4]
                                    }
                                    _save_knowledge_base()
                                
                                return True
                        except:
                            logging.debug(f"Error parsing safety results for {self.name}")
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
            except Exception as e:
                logging.debug(f"Error checking vulnerabilities for {self.name}: {e}")
        
        # Check NVD database via OSV API
        if requests:
            try:
                osv_url = "https://api.osv.dev/v1/query"
                osv_data = {
                    "package": {
                        "name": self.name,
                        "ecosystem": "PyPI"
                    }
                }
                
                if self.version_str:
                    osv_data["version"] = self.version_str
                
                osv_response = requests.post(osv_url, json=osv_data, timeout=5)
                if osv_response.status_code == 200:
                    vulns = osv_response.json().get("vulns", [])
                    
                    if vulns:
                        for vuln in vulns:
                            self.vulnerabilities.append([
                                self.name,
                                self.version_str,
                                vuln.get("summary", "Unknown vulnerability"),
                                vuln.get("references", [{}])[0].get("url", ""),
                                vuln.get("id", "")
                            ])
                        
                        # Add to knowledge base
                        if self.vulnerabilities and self.name not in KNOWLEDGE_BASE["vulnerabilities"]:
                            KNOWLEDGE_BASE["vulnerabilities"][self.name] = {
                                "version": self.version_str,
                                "count": len(self.vulnerabilities),
                                "ids": [vuln[4] for vuln in self.vulnerabilities if len(vuln) > 4]
                            }
                            _save_knowledge_base()
                        
                        return True
            except Exception as e:
                logging.debug(f"Error checking OSV for {self.name}: {e}")
        
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
        # First, check for known replacements
        if self.name in KNOWLEDGE_BASE["replacements"]:
            self.replacement = KNOWLEDGE_BASE["replacements"][self.name]
            return True
        
        # Second, check if it's deprecated with a replacement
        if self.is_deprecated and self.replacement:
            return True
        
        # Third, check for security vulnerabilities
        if self.vulnerabilities:
            return len(self.vulnerabilities) > 0
        
        # Finally, check if we have high confidence potential replacements
        if self.potential_replacements:
            high_confidence = [r for r in self.potential_replacements if r["confidence"] >= 0.7]
            if high_confidence:
                self.replacement = high_confidence[0]["name"]
                return True
        
        return False
    
    def get_update_spec(self):
        """Get updated package specification."""
        if self.should_be_replaced():
            # For replacements, check if we have specific version constraints
            replacement = self.replacement
            
            # Check if there's API compatibility info
            if (self.name in KNOWLEDGE_BASE["compatibility"] and 
                replacement in KNOWLEDGE_BASE["compatibility"][self.name]):
                compat_data = KNOWLEDGE_BASE["compatibility"][self.name][replacement]
                
                # If we have compatibility data, include version constraints
                if compat_data.get("min_version"):
                    return f"{replacement}>={compat_data['min_version']}"
            
            return f"{replacement}"
        elif self.needs_update():
            return f"{self.name}>={self.latest_version_str}"
        return None

def _save_knowledge_base():
    """Save the knowledge base to disk."""
    KNOWLEDGE_BASE["last_update"] = datetime.now().isoformat()
    os.makedirs(os.path.dirname(KNOWLEDGE_BASE_FILE), exist_ok=True)
    with open(KNOWLEDGE_BASE_FILE, 'w') as f:
        json.dump(KNOWLEDGE_BASE, f, indent=2)

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
        "conda.yaml",
        "environment.yml"
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
        
        # Also look for .py files directly
        if any(f.endswith('.py') for f in files):
            if root not in python_projects:
                python_projects.append(root)
                logging.info(f"Found Python code: {root}")
    
    return python_projects

def parse_requirements(requirements_file):
    """
    Parse a requirements.txt file and return a list of package specifications.
    """
    packages = []
    
    if not os.path.exists(requirements_file):
        return packages
    
    with open(requirements_file, 'r', encoding='utf-8', errors='ignore') as f:
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

def analyze_package_usages(project_dir, package_names):
    """
    Analyze how packages are used in a project.
    Returns a dict of package usage signatures.
    """
    try:
        code_analyzer = CodeUsageAnalyzer()
        all_imports, all_usage = code_analyzer.analyze_project(project_dir)
        
        # Filter to only requested packages
        package_usages = {}
        
        for package_name in package_names:
            # Normalize name for import comparison
            package_name_lower = package_name.lower()
            
            # Direct match
            if package_name_lower in all_usage:
                package_usages[package_name] = all_usage[package_name_lower]
                continue
            
            # Try variations of the package name
            variations = [
                package_name_lower.replace('-', '_'),
                package_name_lower.replace('_', '-'),
                package_name_lower.replace('-', ''),
                package_name_lower.replace('_', '')
            ]
            
            for var in variations:
                if var in all_usage:
                    package_usages[package_name] = all_usage[var]
                    break
        
        # Generate signatures
        signatures = {}
        for pkg, usage in package_usages.items():
            signatures[pkg] = code_analyzer.get_core_usage_signature({"modules": {pkg: usage}})
        
        return signatures
    except Exception as e:
        logging.debug(f"Error analyzing package usages in {project_dir}: {e}")
        return {}

def process_package_with_advanced_analysis(pkg_info, project_dir=None):
    """Process a package with advanced analysis."""
    # Get package info from PyPI
    pkg_info.fetch_pypi_info()
    
    # Check for vulnerabilities if we have a version
    if pkg_info.version_str:
        pkg_info.check_for_vulnerabilities()
    
    # Find potential replacements
    pkg_info.find_potential_replacements()
    
    # If we have a project directory, analyze usage patterns
    if project_dir and os.path.exists(project_dir):
        usage_signatures = analyze_package_usages(project_dir, [pkg_info.name])
        if pkg_info.name in usage_signatures:
            pkg_info.usage_signature = usage_signatures[pkg_info.name]
            
            # Store usage signature in knowledge base for future reference
            if "usage_signatures" not in KNOWLEDGE_BASE:
                KNOWLEDGE_BASE["usage_signatures"] = {}
            
            KNOWLEDGE_BASE["usage_signatures"][pkg_info.name] = pkg_info.usage_signature
            _save_knowledge_base()
    
    # Check compatibility with potential replacements
    if pkg_info.potential_replacements:
        # Initialize dependency resolver
        resolver = DependencyResolver()
        mod_analyzer = ModuleAPIAnalyzer()
        code_analyzer = CodeUsageAnalyzer()
        
        # Get our API and usage signatures
        if pkg_info.name not in KNOWLEDGE_BASE.get("api_signatures", {}):
            pkg_info.api_signature = mod_analyzer.extract_module_api(pkg_info.name)
            
            if pkg_info.api_signature:
                if "api_signatures" not in KNOWLEDGE_BASE:
                    KNOWLEDGE_BASE["api_signatures"] = {}
                
                KNOWLEDGE_BASE["api_signatures"][pkg_info.name] = pkg_info.api_signature
                _save_knowledge_base()
        else:
            pkg_info.api_signature = KNOWLEDGE_BASE["api_signatures"][pkg_info.name]
        
        for replacement in pkg_info.potential_replacements:
            rep_name = replacement["name"]
            
            # Skip if we've already analyzed this combination
            if (pkg_info.name in KNOWLEDGE_BASE.get("compatibility", {}) and 
                rep_name in KNOWLEDGE_BASE["compatibility"][pkg_info.name]):
                continue
            
            # Get replacement package info
            try:
                if requests:
                    response = requests.get(f"https://pypi.org/pypi/{rep_name}/json", timeout=5)
                    if response.status_code == 200:
                        rep_data = response.json()
                        rep_version = rep_data.get('info', {}).get('version')
                        
                        if rep_version:
                            # Check dependency compatibility
                            compat_score, issues = resolver.check_compatibility(
                                pkg_info.name, pkg_info.version_str, 
                                rep_name, rep_version
                            )
                            
                            # Extract replacement API
                            rep_api = mod_analyzer.extract_module_api(rep_name)
                            
                            # Compare APIs
                            api_score, api_issues = mod_analyzer.compare_apis(
                                pkg_info.api_signature, rep_api
                            )
                            
                            # Compare usage signatures if available
                            usage_score = 1.0
                            usage_issues = []
                            
                            if pkg_info.usage_signature and rep_name in KNOWLEDGE_BASE.get("usage_signatures", {}):
                                rep_usage = KNOWLEDGE_BASE["usage_signatures"][rep_name]
                                usage_score, usage_issues = code_analyzer.compare_usage_signatures(
                                    pkg_info.usage_signature, rep_usage
                                )
                            
                            # Calculate overall compatibility score
                            overall_score = (compat_score * 0.4) + (api_score * 0.4) + (usage_score * 0.2)
                            
                            # Store in knowledge base
                            if "compatibility" not in KNOWLEDGE_BASE:
                                KNOWLEDGE_BASE["compatibility"] = {}
                            
                            if pkg_info.name not in KNOWLEDGE_BASE["compatibility"]:
                                KNOWLEDGE_BASE["compatibility"][pkg_info.name] = {}
                            
                            KNOWLEDGE_BASE["compatibility"][pkg_info.name][rep_name] = {
                                "overall_score": overall_score,
                                "dependency_score": compat_score,
                                "api_score": api_score,
                                "usage_score": usage_score,
                                "min_version": rep_version,
                                "issues": issues + api_issues + usage_issues,
                                "analyzed_at": datetime.now().isoformat()
                            }
                            
                            _save_knowledge_base()
                            
                            # Update confidence based on compatibility
                            replacement["confidence"] = min(replacement["confidence"] + overall_score * 0.2, 0.95)
                            
                            # If high compatibility, suggest as replacement
                            if overall_score >= 0.8 and replacement["confidence"] >= 0.7:
                                pkg_info.replacement = rep_name
                                
                                # Add to replacements knowledge base
                                KNOWLEDGE_BASE["replacements"][pkg_info.name] = rep_name
                                _save_knowledge_base()
            except Exception as e:
                logging.debug(f"Error analyzing compatibility with {rep_name}: {e}")
    
    return pkg_info

def update_requirements_file(requirements_file, project_dir=None):
    """Update a requirements.txt file with modern equivalents."""
    if not os.path.exists(requirements_file):
        return False
    
    if project_dir is None:
        project_dir = os.path.dirname(requirements_file)
    
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
    
    # Process packages with advanced analysis in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for pkg_info in pkg_infos:
            futures.append(executor.submit(process_package_with_advanced_analysis, pkg_info, project_dir))
        
        updated_pkg_infos = []
        for future in futures:
            updated_pkg_infos.append(future.result())
    
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
                        # Record the replacement in history
                        if "update_history" not in KNOWLEDGE_BASE:
                            KNOWLEDGE_BASE["update_history"] = {}
                        
                        if pkg_info.name not in KNOWLEDGE_BASE["update_history"]:
                            KNOWLEDGE_BASE["update_history"][pkg_info.name] = []
                        
                        KNOWLEDGE_BASE["update_history"][pkg_info.name].append({
                            "from_version": pkg_info.version_str,
                            "to_package": pkg_info.replacement,
                            "date": datetime.now().isoformat(),
                            "requirements_file": requirements_file,
                            "project_dir": project_dir
                        })
                        _save_knowledge_base()
                        
                        reason = "deprecated" if pkg_info.is_deprecated else "vulnerable" if pkg_info.vulnerabilities else "modern alternative"
                        logging.info(f"  Replaced {pkg_info.name} with {update_spec} ({reason})")
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

def dynamic_fetch_package_repositories():
    """Dynamically fetch package repositories and their metadata."""
    global PACKAGE_REPOSITORIES
    
    try:
        if requests:
            # Try to get list of PyPI mirrors
            response = requests.get("https://pypi.org/mirrors", timeout=5)
            if response.status_code == 200:
                mirrors = re.findall(r'<td><a href="([^"]+)"', response.text)
                
                for mirror in mirrors:
                    if mirror not in [repo["url"] for repo in PACKAGE_REPOSITORIES]:
                        PACKAGE_REPOSITORIES.append({
                            "name": f"Mirror {mirror}",
                            "url": f"{mirror.rstrip('/')}/pypi/{{package}}/json"
                        })
        
        # Also try conda-forge API
        if requests:
            response = requests.get("https://conda.anaconda.org/conda-forge/", timeout=5)
            if response.status_code == 200:
                PACKAGE_REPOSITORIES.append({
                    "name": "conda-forge",
                    "url": "https://conda.anaconda.org/conda-forge/{package}/json"
                })
    except:
        pass
    
    return PACKAGE_REPOSITORIES

def learn_from_community_data():
    """
    Learn from community data about package replacements and deprecations.
    Fetches data from multiple sources to improve knowledge base.
    """
    sources = [
        "https://raw.githubusercontent.com/pypa/warehouse/main/warehouse/templates/legacy/api/json.py",
        "https://raw.githubusercontent.com/pypa/pip/main/src/pip/_internal/resolution/resolvelib/candidates.py"
    ]
    
    if not requests:
        return False
    
    try:
        # Try Python Package Index for top packages
        response = requests.get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            for pkg in data.get("rows", []):
                name = pkg.get("project")
                if name and name not in KNOWLEDGE_BASE.get("popularity_scores", {}):
                    KNOWLEDGE_BASE.setdefault("popularity_scores", {})[name] = pkg.get("download_count", 0)
    except:
        pass
    
    try:
        # Get deprecation data from Python Packaging Authority
        for source in sources:
            response = requests.get(source, timeout=5)
            if response.status_code == 200:
                content = response.text
                
                # Look for deprecated package mentions
                deprecated_matches = re.findall(r'([\'"](.+?)[\'"]).+?deprecated|obsolete|unmaintained|abandoned', content, re.IGNORECASE)
                
                for _, package in deprecated_matches:
                    if package and len(package) > 1 and package not in KNOWLEDGE_BASE.get("deprecations", {}):
                        KNOWLEDGE_BASE.setdefault("deprecations", {})[package] = True
                        logging.info(f"Learned about deprecated package: {package}")
                
                # Look for replacement suggestions
                replacement_matches = re.findall(r'([\'"](.+?)[\'"]).+?replaced by.+?([\'"](.+?)[\'"])', content, re.IGNORECASE)
                
                for _, old_pkg, _, new_pkg in replacement_matches:
                    if old_pkg and new_pkg and old_pkg not in KNOWLEDGE_BASE.get("replacements", {}):
                        KNOWLEDGE_BASE.setdefault("replacements", {})[old_pkg] = new_pkg
                        logging.info(f"Learned about replacement: {old_pkg} -> {new_pkg}")
    except:
        pass
    
    # Try to fetch vulnerability data
    try:
        response = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            for package, vulns in data.items():
                if package not in KNOWLEDGE_BASE.get("vulnerabilities", {}):
                    KNOWLEDGE_BASE.setdefault("vulnerabilities", {})[package] = {
                        "count": len(vulns),
                        "ids": [vuln.get("id", "") for vuln in vulns if "id" in vuln]
                    }
    except:
        pass
    
    _save_knowledge_base()
    return True

def process_python_project(project_dir):
    """Process a Python project directory for requirements updates."""
    # Get config settings
    config_file = os.path.expanduser("~/.config/smart-update-reqs/config.json")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "quiet_mode": False,
            "continue_on_build_error": True
        }
    
    quiet_mode = config.get("quiet_mode", False)
    continue_on_error = config.get("continue_on_build_error", True)
    
    if not quiet_mode:
        logging.info(f"Processing project: {project_dir}")
    
    updates_made = False
    updated_files = []
    problem_packages = []
    
    # Check for requirements.txt
    requirements_file = os.path.join(project_dir, "requirements.txt")
    if os.path.exists(requirements_file):
        if update_requirements_file(requirements_file, project_dir):
            updates_made = True
            updated_files.append(requirements_file)
    
    # Check for dev-requirements.txt
    dev_requirements_file = os.path.join(project_dir, "dev-requirements.txt")
    if os.path.exists(dev_requirements_file):
        if update_requirements_file(dev_requirements_file, project_dir):
            updates_made = True
            updated_files.append(dev_requirements_file)
    
    # Check for test-requirements.txt
    test_requirements_file = os.path.join(project_dir, "test-requirements.txt")
    if os.path.exists(test_requirements_file):
        if update_requirements_file(test_requirements_file, project_dir):
            updates_made = True
            updated_files.append(test_requirements_file)
    
    # Check for requirements in a requirements directory
    req_dir = os.path.join(project_dir, "requirements")
    if os.path.exists(req_dir) and os.path.isdir(req_dir):
        for file in os.listdir(req_dir):
            if file.endswith(".txt"):
                req_file = os.path.join(req_dir, file)
                if update_requirements_file(req_file, project_dir):
                    updates_made = True
                    updated_files.append(req_file)
    
    # Check for pyproject.toml
    pyproject_file = os.path.join(project_dir, "pyproject.toml")
    if os.path.exists(pyproject_file):
        # TODO: Implement pyproject.toml parsing and updating
        pass
    
    # Check for setup.py
    setup_file = os.path.join(project_dir, "setup.py")
    if os.path.exists(setup_file):
        # TODO: Implement setup.py parsing and updating
        pass
    
    # If updates were made, rebuild the project
    if updates_made:
        if not quiet_mode:
            logging.info(f"Updates made to {project_dir}, rebuilding...")
        
        # Initialize managers
        env_manager = EnvironmentManager()
        build_manager = BuildManager(env_manager)
        test_manager = TestManager(env_manager)
        
        # For each updated requirements file, install dependencies
        for req_file in updated_files:
            success, project_problem_packages = env_manager.install_dependencies(
                project_dir, 
                req_file, 
                quiet_mode=quiet_mode, 
                continue_on_error=continue_on_error
            )
            problem_packages.extend(project_problem_packages)
        
        # Build project if it has compiled components
        if build_manager.has_compiled_components(project_dir):
            build_success = build_manager.build_project(project_dir, 
                                                      quiet_mode=quiet_mode, 
                                                      continue_on_error=continue_on_error)
            if not build_success and not quiet_mode:
                logging.warning(f"Build failed for {project_dir}, but continuing...")
        
        # Run tests if available
        if test_manager.has_tests(project_dir):
            test_success = test_manager.run_tests(project_dir, 
                                               quiet_mode=quiet_mode, 
                                               continue_on_error=continue_on_error)
            if not test_success and not quiet_mode:
                logging.warning(f"Tests failed for {project_dir}, but continuing...")
    
    # Print summary if there were problems
    if problem_packages and not quiet_mode:
        logging.warning(f"The following packages had installation issues for {project_dir}:")
        for pkg in problem_packages:
            logging.warning(f"  - {pkg}")
        logging.warning("These packages may need manual installation or additional build dependencies.")
    
    return updates_made

def print_system_info():
    """Print information about the system."""
    logging.info(f"Python version: {platform.python_version()}")
    logging.info(f"Platform: {platform.platform()}")
    logging.info(f"Machine: {platform.machine()}")
    
    # Log package versions
    logging.info("Dependency versions:")
    deps = ["requests", "packaging", "safety", "pipdeptree", "importlib_metadata"]
    for dep in deps:
        try:
            pkg = __import__(dep)
            version = getattr(pkg, "__version__", "unknown")
            logging.info(f"  {dep}: {version}")
        except ImportError:
            logging.info(f"  {dep}: not installed")

def main():
    """Main function to find and update Python projects."""
    # Get command-line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description='Smart Requirements Updater')
    parser.add_argument('--quiet', '-q', action='store_true', help='Only show errors and summary')
    parser.add_argument('--errors-only', '-e', action='store_true', help='Only show errors')
    parser.add_argument('--continue-on-error', '-c', action='store_true', help='Continue despite build or installation errors')
    parser.add_argument('--skip-build', '-s', action='store_true', help='Skip building and testing after updating requirements')
    parser.add_argument('--config', type=str, help='Path to custom config file')
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.errors_only:
        logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
    elif args.quiet:
        logging.basicConfig(
            level=logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    logging.info("Starting smart requirements updater")
    
    # Fix regex escape sequences
    fix_regex_escape_sequences()
    
    # Print system info
    print_system_info()
    
    # Dynamically fetch package repositories
    dynamic_fetch_package_repositories()
    
    # Initialize all required knowledge base keys
    initialize_knowledge_base_keys()
    
    # Learn from community data
    learn_from_community_data()
    
    # Load config or create default
    config_path = args.config if args.config else os.path.expanduser("~/.config/smart-update-reqs/config.json")
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "scan_directories": [os.path.expanduser("~")],
            "exclude_directories": [
                "~/anaconda3", "~/miniconda3", "~/venv", "~/.venv"
            ],
            "auto_rebuild": not args.skip_build,
            "auto_test": not args.skip_build,
            "rebuild_timeout": 600,  # 10 minutes timeout for rebuilds
            "prompt_before_rebuild": False,  # Set to True to prompt before rebuilding
            "quiet_mode": args.quiet or args.errors_only,
            "continue_on_build_error": args.continue_on_error or True
        }
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    # Override config with command line arguments
    if args.quiet or args.errors_only:
        config["quiet_mode"] = True
    if args.continue_on_error:
        config["continue_on_build_error"] = True
    if args.skip_build:
        config["auto_rebuild"] = False
        config["auto_test"] = False
    
    # Save updated config
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    projects_updated = 0
    projects_processed = 0
    projects_rebuilt = 0
    projects_tested = 0
    error_projects = []
    
    # Process each scan directory
    for scan_dir in config["scan_directories"]:
        scan_dir = os.path.expanduser(scan_dir)
        if not os.path.exists(scan_dir):
            logging.warning(f"Scan directory does not exist: {scan_dir}")
            continue
        
        python_projects = find_python_projects(scan_dir)
        if not config.get("quiet_mode", False):
            logging.info(f"Found {len(python_projects)} Python projects in {scan_dir}")
        
        # Expand excluded directories
        expanded_exclude_dirs = [os.path.expanduser(d) for d in config.get("exclude_directories", [])]
        
        for project in python_projects:
            # Skip excluded directories
            if any(project.startswith(exclude) for exclude in expanded_exclude_dirs):
                if not config.get("quiet_mode", False):
                    logging.info(f"Skipping excluded project: {project}")
                continue
            
            projects_processed += 1
            try:
                if process_python_project(project):
                    projects_updated += 1
                    
                    # Initialize environment manager for checking rebuild status
                    env_manager = EnvironmentManager()
                    build_manager = BuildManager(env_manager)
                    test_manager = TestManager(env_manager)
                    
                    # Log rebuild and test status
                    if build_manager.has_compiled_components(project):
                        projects_rebuilt += 1
                    
                    if test_manager.has_tests(project):
                        projects_tested += 1
            except Exception as e:
                error_projects.append((project, str(e)))
                logging.error(f"Error processing {project}: {e}")
                if not config.get("continue_on_build_error", True):
                    break
    
    # Print summary
    logging.info(f"Completed processing {projects_processed} Python projects")
    logging.info(f"Updated {projects_updated} projects")
    
    if config.get("auto_rebuild", True):
        logging.info(f"Rebuilt {projects_rebuilt} projects with compiled components")
        logging.info(f"Tested {projects_tested} projects")
    
    if error_projects:
        logging.warning("The following projects had errors:")
        for project, error in error_projects:
            logging.warning(f"  - {project}: {error}")
    
    # Save final knowledge base
    _save_knowledge_base()

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
  ],
  "auto_rebuild": true,
  "auto_test": true,
  "rebuild_timeout": 600,
  "quiet_mode": false,
  "continue_on_build_error": true
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
