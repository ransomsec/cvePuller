NAME=cvePuller

linux:
	GOOS=linux GOARCH=amd64 go build -o ${NAME}-linux -ldflags='-s -w'
windows:
	GOOS=windows GOARCH=amd64 go build -o ${NAME}-windows.exe
clean:
	go clean
	rm -rf ${NAME}*

