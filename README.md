# Retrowrite

Retrowrite is a static binary rewriter for x64 and aarch64. It works without
heuristics, does not introduce overhead and uses the *symbolization* technique
(also known as *reassemblable assembly*) to insert instrumentation to binaries
without the need for source code.

Please note that the x64 version and the arm64 version use different rewriting algorithms and
support a different set of features. 

For technical details, you can read the 
[paper](https://nebelwelt.net/publications/files/20Oakland.pdf)
(in *IEEE S&P'20*) for the x64 version and this [thesis](https://hexhive.epfl.ch/theses/20-dibartolomeo-thesis.pdf) 
for the arm64 version. 

[KRetrowrite](#kretrowrite) is a variant of the x64 version that supports the rewriting
of Linux kernel modules. 

做出一些修改。
