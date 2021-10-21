## eBPF Programming - XDP networking
Example of User-space and kernel-space interaction

### Compile kernel-space code

```
clang -O2 -g -Wall -target bpf -c xdp_kern.c -o bin/xdp_kern.o
```

