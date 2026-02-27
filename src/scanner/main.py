import ast

class SecurityScanner(ast.NodeVisitor):
    
    def visit_Call(self, node):
        
        #Start checking for os function calls
        if isinstance(node.func, ast.Attribute):
            #Checking for os.system()
            if getattr(node.func.value, "id", None) == "os" and node.func.attr == "system":
                print("os.system() within code, this could be a secuirty vunerlability")

dummyCode = """
import os

def backup_data(folder_name):
    # DANGER: User input is passed directly to the shell
    os.system("cp -r " + folder_name + " /backup")
    print("Backup complete!")

backup_data("my_files")
"""

parsedCode = ast.parse(dummyCode)
Scanner = SecurityScanner()
Scanner.visit(parsedCode)