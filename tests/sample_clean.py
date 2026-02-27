import subprocess

#Safe subprocess (shell defaults to False)
subprocess.run(["ls", "-la"])

#Normal print (Not eval or exec)
print("This is a safe string")

#A variable named 'system' but not 'os.system'
system = "normal_string"