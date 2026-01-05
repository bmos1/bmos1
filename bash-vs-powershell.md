# Cheatsheet Bash vs. Powershell

## Writing and reading files without editors

Bash

```bash
# Set content
cat << 'EOF' > test.txt
Some content
EOF
# Add content
cat << 'EOF' >> test.txt
More content
EOF
# Get content
cat test.txt
```

Powershell

```powershell
# Set content
@'
Some content
'@ | Set-Content test.txt
# Add content
@'
More content
'@ | Add-Content test.txt
# Get content
Get-Content test.txt
```

Windows Cmd

```shell
@:: Set content
( 
echo Some Content 
) > test.txt
@:: Add content
( 
echo More Content 
) >> test.txt
@:: Get content
type test.txt
```


