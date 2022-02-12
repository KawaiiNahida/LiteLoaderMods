@ECHO OFF
echo "Building Golang Plugin LibWebsocket.dll"
go build -v -ldflags "-s -w" -buildmode=c-shared -o LibWebsocket.dll websocket.go || goto buildfailed
echo "Running upx --best"
upx --best --lzma LibWebsocket.dll || goto packfailed
echo "Finished Building and Packing"
pause
exit

:buildfailed
echo "Building Golang Failed!!!!!!"
goto pause

:packfailed
echo "Packing Failed!!!!!!"
goto pause

:pause
echo "An Error Occur While BuildingPlugin"
pause