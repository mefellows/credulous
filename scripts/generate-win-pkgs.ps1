mkdir $env:GOPATH/src/github.com/libgit2 
cd $GOPATH/src/github.com/libgit2 
git clone https://github.com/libgit2/git2go.git
cd git2go
git checkout next
rmdir -recurse -force vendor
git submodule update --init
<#
cd vendor/libgit2
mkdir build
cd build
$env:GENERATOR="Visual Studio 12 Win64"
cmake -D ENABLE_TRACE=ON -D BUILD_CLAR=ON .. -G"$env:GENERATOR"
cmake --build . --config RelWithDebInfo
cd ../../../
#>
make install

cd git2go 
git submodule update --init
make install
cd $TRAVIS_BUILD_DIR
go get -v -t ./...
mkdir -p $HOME/gopath/bin
go install
