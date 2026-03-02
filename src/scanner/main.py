import ast

class SecurityScanner(ast.NodeVisitor):
    
    def scan(self, tree):
        #Walks through the tree and yeilds reports one by one
        for node in ast.walk(tree):
            
            result = self.visit(node)
            if result:
                yield from result

    def report(self, node, message):

        output = f"[!]Line {node.lineno}: {message}"
        yield output

    def visit_Call(self, node):
        #Cheacking for atrribute function calls
        if isinstance(node.func, ast.Attribute):
        
            #Checking for os.system()
            if getattr(node.func.value, "id", None) == "os" and node.func.attr == "system":
                yield from self.report(node, "os.system() detected (Possible Command Injection).")
            #Checking for shelx.quote()
            if getattr(node.func.value, "id", None) == "shlex" and node.func.attr == "quote":
                yield from self.report(node, "shlex.quote() detected.")

            #Checking for subprocess
            if getattr(node.func.value, "id", None) == "subprocess":

                #Checking for shell=True in functions arguments
                for kw in node.keywords:
                    keyWord = kw.arg
                    valueUnparsed = ast.unparse(kw.value)

                    if keyWord == "shell" and valueUnparsed == "True":
                        yield from self.report(node, "subprocess with shell=True detected.")
                    
        #Checking for stand alone function calls
        if isinstance(node.func, ast.Name):

            #Checking eval()
            if node.func.id == "eval" or node.func.id =="exec" or node.func.id == "compile":
                yield from self.report(node, f"{node.func.id}() detected (Possible Code Injection).")
