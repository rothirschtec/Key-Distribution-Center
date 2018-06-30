SET mypath=%~dp0
certutil -f -p !!Password!! -importpfx  %mypath:~0,-1%\p12\!!Certificate!!
cmd \k
