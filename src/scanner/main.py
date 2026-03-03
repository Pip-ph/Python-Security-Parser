import ast

class SecurityScanner(ast.NodeVisitor):
    
    def __init__(self):
        self.vulnerabilitiesFound = 0
        self.tainted_vars = set()

    def scan(self, tree):
        #Walks through the tree and yeilds reports one by one
        for node in ast.walk(tree):
            
            result = self.visit(node)
            if result:
                yield from result

    def report(self, node, message):

        output = f"[!]Line {node.lineno}: {message}"
        yield output

    def visit_Assign(self, node):
        is_input = False
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == "input":
                is_input = True
        
        #Check if its assinged a tainted varibale
        is_propagated = False
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            is_propagated = True

        #If its tainted add to the set
        if is_input or is_propagated:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        
        #Comment:Checking for untaint/sanitization
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in ["int", "float"]:
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in self.tainted_vars:
                        self.tainted_vars.remove(target.id)
        

    def visit_Call(self, node):
        #Comment:Function to check if any argument is tainted
        def is_arg_tainted(args):
            for arg in args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    return True, arg.id
            return False, None

        #Cheacking for atrribute function calls
        if isinstance(node.func, ast.Attribute):
        
            #Checking for os.system()
            if getattr(node.func.value, "id", None) == "os" and node.func.attr == "system":
                #Comment:Check if the argument in os.system is tainted
                tainted, var_name = is_arg_tainted(node.args)
                if tainted:
                    self.vulnerabilitiesFound +=1
                    yield from self.report(node, f"os.system() with tainted variable '{var_name}' detected!")
                else:
                    self.vulnerabilitiesFound +=1
                    yield from self.report(node, "os.system() detected (Possible Command Injection).")
            
            #Checking for shelx.quote()
            if getattr(node.func.value, "id", None) == "shlex" and node.func.attr == "quote":
                self.vulnerabilitiesFound +=1
                yield from self.report(node, "shlex.quote() detected.")

            #Checking for subprocess
            if getattr(node.func.value, "id", None) == "subprocess":

                #Checking for shell=True in functions arguments
                for kw in node.keywords:
                    keyWord = kw.arg
                    valueUnparsed = ast.unparse(kw.value)

                    if keyWord == "shell" and valueUnparsed == "True":
                        #Comment:Check if the first argument (the command) is tainted
                        tainted, var_name = is_arg_tainted(node.args)
                        if tainted:
                            self.vulnerabilitiesFound +=1
                            yield from self.report(node, f"subprocess with shell=True and tainted variable '{var_name}' detected!")
                        else:
                            self.vulnerabilitiesFound +=1
                            yield from self.report(node, "subprocess with shell=True detected.")
                    
        #Checking for stand alone function calls
        if isinstance(node.func, ast.Name):

            #Checking eval()
            if node.func.id == "eval" or node.func.id =="exec" or node.func.id == "compile":
                #Comment:Check if the argument is tainted
                tainted, var_name = is_arg_tainted(node.args)
                if tainted:
                    self.vulnerabilitiesFound +=1
                    yield from self.report(node, f"{node.func.id}() with tainted variable '{var_name}' detected!")
                else:
                    self.vulnerabilitiesFound +=1
                    yield from self.report(node, f"{node.func.id}() detected (Possible Code Injection).")