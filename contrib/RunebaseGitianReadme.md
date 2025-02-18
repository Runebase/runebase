## Set env var

```

export SIGNER=Bago213
export VERSION=0.20.2

```

## linux

```

sudo runebase/contrib/gitian-build-linux.py ${SIGNER} ${VERSION} --build --docker -j12

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-linux-unsigned --destination ../gitian.sigs/ ../runebase/contrib/gitian-descriptors/gitian-linux.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-linux-unsigned ../runebase/contrib/gitian-descriptors/gitian-linux.yml


```

## windows

```

sudo runebase/contrib/gitian-build-windows.py ${SIGNER} ${VERSION} --build --docker -j12

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-windows-unsigned --destination ../gitian.sigs/ ../runebase/contrib/gitian-descriptors/gitian-windows.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-windows-unsigned ../runebase/contrib/gitian-descriptors/gitian-windows.yml

```

## mac

```

sudo runebase/contrib/gitian-build-osx.py ${SIGNER} ${VERSION} --build --docker -j12

sudo ./bin/gsign --signer ${SIGNER} --release ${VERSION}-osx-unsigned --destination ../gitian.sigs/ ../runebase/contrib/gitian-descriptors/gitian-osx.yml

./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-osx-unsigned ../runebase/contrib/gitian-descriptors/gitian-osx.yml


```
