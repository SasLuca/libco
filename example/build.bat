@echo off
if not exist build mkdir build
pushd build
cl -nologo /Zi ../example.c /link /out:example.exe
popd