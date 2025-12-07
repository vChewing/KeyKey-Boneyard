.PHONY: all

all:
	dotnet clean && dotnet restore && dotnet build --no-restore && dotnet test --no-build

.PHONY: format pack

format:
	dotnet format
	# find . -regex '.*\.\(cs\)' -exec clang-format -style=file -i {} \;

pack:
	dotnet build KeyKeyUserDBKit/KeyKeyUserDBKit.csproj --configuration Release
	dotnet pack KeyKeyUserDBKit/KeyKeyUserDBKit.csproj --configuration Release --no-build --output ./nupkg
