import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import ast
from src.scanner.main import SecurityScanner 

def start_scan(file_content):
    """Takes the code string, parses it, and runs the generator."""
    report_area.delete("1.0", tk.END)
    report_area.insert(tk.END, "--- Analysis Started ---\n")
    
    try:
        tree = ast.parse(file_content)
        scanner = SecurityScanner()
        
        found_any = False
        for finding in scanner.scan(tree):
            found_any = True
            report_area.insert(tk.END, finding + "\n", "warning")
            window.update_idletasks() 
        
        if not found_any:
            report_area.insert(tk.END, "✔ Scan Complete: No issues found.\n")
            
    except Exception as e:
        report_area.insert(tk.END, f"Parsing Error: {e}\n")

def get_file():
    filepath = filedialog.askopenfilename(
        filetypes=(("Python files", "*.py"), ("All files", "*.*"))
    )
    
    if filepath:
        try:
            with open(filepath, "r") as f:
                content = f.read()
            #Immediately pass the code to the scanner logic
            start_scan(content)
        except Exception as e:
            messagebox.showerror("File Error", f"Could not read file: {e}")

#Tkinter 
window = tk.Tk()
window.title("Python Security Parser")
window.geometry('800x500') 

#Styling the output
report_area = scrolledtext.ScrolledText(window, height=20, bg="black", fg="white")
report_area.tag_config("warning", foreground="red")

choose_button = tk.Button(
    window, 
    text="Select Python File to Scan", 
    command=get_file, 
    activebackground="yellow",
    font=("Arial", 12, "bold")
)

#Grid Layout
for i in range(4):
    window.columnconfigure(i, weight=1)
    window.rowconfigure(i, weight=1)

choose_button.grid(row=0, column=0, columnspan=4, sticky="NSEW", padx=10, pady=10)
report_area.grid(row=1, column=0, columnspan=4, rowspan=3, sticky="NSEW", padx=10, pady=10)

window.mainloop()