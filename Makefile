build:
	go mod tidy
	env GOOS=linux  GOARCH=arm64 go build -o aws-auth_linux_arm64
	env GOOS=linux  GOARCH=amd64 go build -o aws-auth_linux_amd64
	env GOOS=darwin GOARCH=arm64 go build -o aws-auth_darwin_arm64
	env GOOS=darwin GOARCH=amd64 go build -o aws-auth_darwin_amd64
