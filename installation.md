## install python
- https://www.python.org/downloads/release/python-3112/
- >=python3.11 will be fine

## install libs
`pip install -r requirements.txt`

## add appcmd to env
`set PATH=%PATH%;%systemroot%\system32\inetsrv\`

## remove disallowed ips using appcmd.exe
`appcmd.exe set config -section:system.webServer/security/ipSecurity /-"[ipAddress='x.x.x.x',allowed='False']" /commit:apphost`