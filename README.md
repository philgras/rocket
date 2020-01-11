# Rocket - C++ Network Library

At its core, this library provides an epoll-based event 
loop to handle TCP connections. It is designed to be working
in single-threaded and multi-threaded applications. In addition, 
implementations of application protocols (only HTTP at the moment)
are provided.

See `examples/` and `test/` directories for usage examples.

## Todos
As the library is still under development, there is no stable API or something similar.
Also, a lot of features have not been implemented.
\
\
At the moment, most of my development time is spent on:
- TLS support, by using the Botan library
- multi-threaded IO loops

Goals for the future:
- 'stable' API
- Unit tests
- Benchmarks with other libraries in the field
