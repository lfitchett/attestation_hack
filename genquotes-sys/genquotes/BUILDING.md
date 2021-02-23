# Instructions to build
```sh
cd genquote

. /opt/openenclave/share/openenclave/openenclaverc

make build

cd enclave

# There is a failure in building genquote_enclave with latest SDK. Use the following commands in genquote/enclave folder to complete the rest of the build for now
clang++-8 -o genquote_enclave attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o -L/opt/openenclave/share/pkgconfig/../../lib/openenclave/enclave -nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,-gc-sections -loeenclave -loelibcxx -loelibc -loesyscall -loecore -loeenclave -loelibc -loesyscall -loecore -loecryptombedtls -lmbedx509 -lmbedtls -lmbedcrypto -loelibc -loesyscall -loecore

cd ..

make sign

cat quotes/enclave.info.debug.json

```

