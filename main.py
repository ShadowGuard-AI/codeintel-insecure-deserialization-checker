import argparse
import logging
import os
import ast
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Files that could not be read or parsed during this run. A failed
# file is not a clean file, so main reports each one as not scanned
# and exits 1 when this list is not empty.
# I keep this list at module level, so a second scan inside the
# same process would inherit the first run's failures. The CLI
# runs once and exits, which is the only reason this is safe.
scan_failures = []

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects potential insecure deserialization vulnerabilities in Python code.")
    parser.add_argument("filepath", help="Path to the Python file or directory to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-e", "--exclude", nargs="+", help="List of files or directories to exclude from analysis.")
    parser.add_argument("-o", "--output", help="Path to output file for scan results.  If omitted, results will be printed to the console.")
    return parser

def analyze_file(filepath, exclude_list=None, output_file=None):
    """
    Analyzes a single Python file for insecure deserialization vulnerabilities.
    Args:
        filepath (str): Path to the Python file.
        exclude_list (list): List of files or directories to exclude.
        output_file (str, optional): Path to the file to write output to.  If None, output will go to stdout.
    Returns:
        list: A list of vulnerability findings.
    """
    findings = []

    # I test exclusions as plain string prefixes. Excluding a path
    # named data also excludes a sibling named database, because
    # no path boundary is checked after the prefix.
    if exclude_list and any(filepath.startswith(exclude) for exclude in exclude_list):
        logging.debug(f"Skipping file: {filepath} (excluded)")
        return findings

    try:
        with open(filepath, 'r') as f:
            content = f.read()
            tree = ast.parse(content)

            # Resolve imports first, so a call is matched by the module
            # it actually came from, not by the spelling at the call
            # site. module_aliases maps a local name to its module
            # (import pickle as pk gives pk -> pickle), and
            # from_imports maps a local name to (module, attribute)
            # (from pickle import loads gives loads -> (pickle, loads)).
            module_aliases = {}
            from_imports = {}
            # I collect every import in the file before I match any call,
            # so an import at the bottom of the file still names a call at
            # the top. Real Python would fail that call, my scan does not.
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split('.')[0]
                        module_aliases[alias.asname or root] = root
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split('.')[0]
                    for alias in node.names:
                        from_imports[alias.asname or alias.name] = (root, alias.name)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    module_name = module_aliases.get(node.func.value.id, node.func.value.id)
                    attr = node.func.attr
                elif isinstance(node.func, ast.Name) and node.func.id in from_imports:
                    module_name, attr = from_imports[node.func.id]
                else:
                    continue
                label = None
                # pickle and its forks execute arbitrary code while loading,
                # which is why a call alone is the finding here, whatever
                # name the module was imported under in this file's header.
                if module_name in ("pickle", "cloudpickle", "dill", "marshal") and attr in ("loads", "load"):
                    label = f"{module_name}.{attr}"
                elif module_name == "jsonpickle" and attr == "decode":
                    # jsonpickle.decode sits directly on the module, so
                    # node.func.value is a Name; a check that required an
                    # Attribute there could never fire.
                    label = "jsonpickle.decode"
                elif module_name == "yaml" and attr == "unsafe_load":
                    label = "yaml.unsafe_load"
                elif module_name == "yaml" and attr == "load":
                    # yaml.load is only safe with SafeLoader (or safe_load);
                    # no Loader keyword, or an unsafe one, keeps the risk.
                    loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
                    loader_name = ""
                    if isinstance(loader, ast.Name):
                        loader_name = loader.id
                    elif isinstance(loader, ast.Attribute):
                        loader_name = loader.attr
                    if "Safe" not in loader_name:
                        label = "yaml.load (no SafeLoader)"
                if label:
                    findings.append({
                        "filepath": filepath,
                        "lineno": node.lineno,
                        "col_offset": node.col_offset,
                        "message": f"Potential insecure deserialization vulnerability: Usage of {label} without proper input validation."
                    })

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        scan_failures.append(filepath)
    except Exception as e:
        logging.error(f"Error analyzing {filepath}: {e}")
        scan_failures.append(filepath)

    return findings


def analyze_directory(dirpath, exclude_list=None, output_file=None):
    """
    Analyzes all Python files in a directory (recursively) for insecure deserialization vulnerabilities.
    Args:
        dirpath (str): Path to the directory.
        exclude_list (list): List of files or directories to exclude.
        output_file (str, optional): Path to the file to write output to.  If None, output will go to stdout.
    Returns:
        list: A list of vulnerability findings.
    """
    findings = []
    for root, _, files in os.walk(dirpath):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                findings.extend(analyze_file(filepath, exclude_list, output_file))
    return findings


def main():
    """
    Main function to drive the insecure deserialization checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    filepath = args.filepath
    exclude_list = args.exclude or []
    output_file = args.output

    if os.path.isfile(filepath):
        findings = analyze_file(filepath, exclude_list, output_file)
    elif os.path.isdir(filepath):
        findings = analyze_directory(filepath, exclude_list, output_file)
    else:
        logging.error(f"Invalid filepath: {filepath}.  File or directory not found.")
        sys.exit(1)
    
    failed_files = list(scan_failures)

    if output_file:
        try:
            with open(output_file, 'w') as f:
                for finding in findings:
                    f.write(f"{finding['filepath']}:{finding['lineno']}:{finding['col_offset']} - {finding['message']}\n")
                for failed in failed_files:
                    f.write(f"Not scanned: {failed}\n")
            logging.info(f"Scan results written to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file {output_file}: {e}")
            sys.exit(1)
        for failed in failed_files:
            print(f"Not scanned: {failed}")

    else:
        if findings:
            print("Insecure Deserialization Vulnerability Findings:")
            for finding in findings:
                print(f"{finding['filepath']}:{finding['lineno']}:{finding['col_offset']} - {finding['message']}")
        for failed in failed_files:
            print(f"Not scanned: {failed}")
        if not findings and not failed_files:
            print("No insecure deserialization vulnerabilities found.")

    # Findings exit 1, matching the other checkers in this set, and a
    # file that failed to scan fails the run instead of passing clean.
    if findings or failed_files:
        sys.exit(1)

if __name__ == "__main__":
    main()