## eBPF Programming
Example of User-space and kernel-space interaction

### Compile kernel-space code

```
clang -O2 -g -Wall -target bpf -c trace_kern.c -o bin/trace_kern.o
```

### Compile user-space code

Build object file
```
clang -g -O2 -Wall -I . -c trace_user.c -o trace_user.o
```

Link with libbpf
```
git clone https://github.com/libbpf/libbpf && cd libbpf/src/
make BUILD_STATIC_ONLY=1 OBJDIR=../build/libbpf DESTDIR=../build INCLUDEDIR= LIBDIR= UAPIDIR= install
```

Build executable file
```
$ clang -Wall -O2 -g trace_user.o libbpf/build/libbpf.a -lelf -lz -o trace
```

Execute file:
```
sudo ./trace
```
