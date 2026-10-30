import argparse
import logging
import os
import ast
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

    if exclude_list and any(filepath.startswith(exclude) for exclude in exclude_list):
        logging.debug(f"Skipping file: {filepath} (excluded)")
        return findings

    try:
        with open(filepath, 'r') as f:
            content = f.read()
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
                    continue
                module_name = node.func.value.id
                attr = node.func.attr
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
    except Exception as e:
        logging.error(f"Error analyzing {filepath}: {e}")

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
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                for finding in findings:
                    f.write(f"{finding['filepath']}:{finding['lineno']}:{finding['col_offset']} - {finding['message']}\n")
            logging.info(f"Scan results written to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file {output_file}: {e}")
            sys.exit(1)

    else:
        if findings:
            print("Insecure Deserialization Vulnerability Findings:")
            for finding in findings:
                print(f"{finding['filepath']}:{finding['lineno']}:{finding['col_offset']} - {finding['message']}")
        else:
            print("No insecure deserialization vulnerabilities found.")

if __name__ == "__main__":
    main()