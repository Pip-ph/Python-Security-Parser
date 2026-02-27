import ast

class SecurityScanner(ast.NodeVisitor):
    
    def visit_Call(self, node):
        #Cheacking for atrribute function calls
        if isinstance(node.func, ast.Attribute):
        
            #Checking for os.system()
            if getattr(node.func.value, "id", None) == "os" and node.func.attr == "system":
                print("os.system() within code, this could be a security vunerlability")

            #Checking for subprocess
            if getattr(node.func.value, "id", None) == "subprocess":

                #Checking for shell=True in functions arguments
                for kw in node.keywords:
                    keyWord = kw.arg
                    valueUnparsed = ast.unparse(kw.value)

                    if keyWord == "shell" and valueUnparsed == "True":
                        print("Subprocess function cointaining shell=True found.This could be a security vunerlability")
                    
        #Checking for stand alone function calls
        if isinstance(node.func, ast.Name):

            #Checking eval()
            if node.func.id == "eval" or node.func.id =="exec":
                print(f"An {node.func.id}() function call is included in the code. This could be a security vunerlability")
