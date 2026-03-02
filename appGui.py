import tkinter as tk
from tkinter import scrolledtext
import ast
from src.scanner.main import SecurityScanner 

def start_scan():
    code = code_input.get("1.0", tk.END)
    report_area.delete("1.0", tk.END)
    report_area.insert(tk.END, "Scanning...\n")
    
    try:
        tree = ast.parse(code)
        scanner = SecurityScanner()
        
        #Loop over the generator
        for finding in scanner.scan(tree):
            
            report_area.insert(tk.END, finding + "\n", "warning")
            root.update_idletasks() 
            
    except Exception as e:
        report_area.insert(tk.END, f"Error: {e}")

#TKinter
root = tk.Tk()
root.title("Security Scanner")

#Input Area
tk.Label(root, text="Paste Code Here:").pack()
code_input = scrolledtext.ScrolledText(root, height=10)
code_input.pack()

#Scan Button
btn = tk.Button(root, text="Run Security Scan", command=start_scan)
btn.pack(pady=10)

#Report Area
tk.Label(root, text="Reports:").pack()
report_area = scrolledtext.ScrolledText(root, height=10, fg="green", bg="black")
report_area.tag_config("warning", foreground="red")
report_area.pack()

root.mainloop()