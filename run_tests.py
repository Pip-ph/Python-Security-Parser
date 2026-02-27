import ast
from src.scanner.main import SecurityScanner

def run_test_on_file(filename):
    print(f"--- Testing File: {filename} ---")
    try:
        with open(filename, "r") as f:
            source = f.read()
        
        #Parse the file into an AST
        tree = ast.parse(source)
        
        #Runner file under the scanner
        scanner = SecurityScanner()
        scanner.visit(tree)
        
    except Exception as e:
        print(f"Error processing file: {e}")
    print("-" * 30 + "\n")

if __name__ == "__main__":
    #Test the vulnerable file
    run_test_on_file("tests/sample_vuln.py")
    #Test the clean file
    run_test_on_file("tests/sample_clean.py")