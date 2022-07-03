import subprocess
result = subprocess.getoutput('ssh -T git@github.com')
print(result)
