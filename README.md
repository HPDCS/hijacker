Hijacker [![Build Status](https://travis-ci.org/HPDCS/hijacker.svg?branch=master)](https://travis-ci.org/HPDCS/hijacker)
=========

Hijacker is a static binary instrumentation tool, targeted at HPC applications. It has seen his light on October, 18th 2012 as an ad-hoc tool to instrument executables for [ROOT-Sim](https://github.com/HPDCS/ROOT-Sim), but has since then been extended and made more versatile. It allows to instrument relocatable object files according to a set of rules which are specified in an xml file.

Installation
------------

In order to compile Hijacker the following dependencies are needed:`libxml2` and `libz`. Make sure that header files are included, too---if you are on Ubuntu, these files are provided respectively by the packages `libxml2-dev` and `libz-dev`.

To compile and install Hijacker, a quick `./configure && make && make install` should do the job. Further information on the available installation flags are provided in the `INSTALL` file.

Usage
-----

Basically, Hijacker accepts two main input files: an xml _rules file_ containing the instrumentation directives that Hijacker has to apply, and a _relocatable file_ (also called _object file_) which is subject to the actual instrumentation.

You can see the program's usage statement by invoking it with `--help`. A typical invocation of Hijacker is:

```
./hijacker -c <rules_file> -i <input_object_file> -o <output_object_file>
```

To include Hijacker into the standard compilation toolchain, it must be invoked after the generation of some object files and before the final linking step.

As an example, suppose you have a program consisting of three different `.c` files: `foo.c`, `bar.c`, `baz.c`. A typical compiler invocation would be able to produce the final executable using a one-liner:

```
gcc foo.c bar.c baz.c -DNDEBUG -lpthread -o program
```

Suppose also that you want to instrument the object file for the module `foo`. The revised compilation process is as follows:

```
# Generate object files
gcc -c foo.c -DNDEBUG -o foo.o
gcc -c bar.c -DNDEBUG -o bar.o
gcc -c baz.c -DNDEBUG -o baz.o

# Instrument foo.o
hijacker -c config.xml -i foo.o -o foo-instr.o

# Final linking step
gcc foo-instr.o bar.o baz.o -lpthread -o program
```

On the other hand, if you want to instrument all object files at once, you must rely on _partial linking_ as follows:

```
# Generate object files
gcc -c foo.c -DNDEBUG -o foo.o
gcc -c bar.c -DNDEBUG -o bar.o
gcc -c baz.c -DNDEBUG -o baz.o

# Partially link object files
ld -r foo.o bar.o baz.o -o program.o

# Instrument foo.o
hijacker -c config.xml -i program.o -o program-instr.o

# Final linking step
gcc program-instr.o -lpthread -o program
```

A more thorough explanation of Hijacker's inner workings, as well as the rules file syntax, is provided in [1] and [2].

[1] A. Pellegrini, "Hijacker: Efficient static software instrumentation with applications in high performance computing: Poster paper," 2013 International Conference on High Performance Computing & Simulation (HPCS), Helsinki, 2013, pp. 650-655.

[2] D. Cingolani, S. Economo and A. Pellegrini, "Hijacker: a static binary instrumentation tool: Poster abstract", 2016 Twelfth International Summer School on Advanced Computer Architecture and Compilation for High-Performance and Embedded Systems (ACACES), Fiuggi, 2016, pp. 207-210.


Selective Memory Tracer (SMT)
=============================
SMT is a tool based upon Hijacker to selectively instrument a subset of instructions that are representative of the actual memory access pattern of the passed object file. The trade-off between overhead and precision of the tracing process is user-tunable, so that it can be set depending on the final objective of memory access tracing. Additionally, our approach can track memory access at different granularity (e.g., virtual-pages, cache line-sized buffers, etc.).

Internally, SMT works as follows (more details can be found in [3]):

1. The input object file code is parsed into a Control Flow Graph (CFG) and each basic block is analyzed to see if it issues memory accesses to arbitrary memory regions.
2. Memory accesses within a basic block are clustered if they use the same registers, constants, and register values to produce a memory address (i.e., the same _memory access expression_). The _cardinality_ of an access is the size of the cluster, which in turn is the number of times an equivalent memory access expression has been found in the basic block via static analysis.
3. Memory accesses can be further aggregated depending on the desired _tracing granularity_ `C`. If two memory access expressions are believed to fall within the same `C`-sized memory region, they are clustered together.
4. For each unique memory access found in the basic block, a score is computed to choose the most representative accesses. This score is affected by the cluster cardinality and the tracing granularity.
5. Some unique memory accesses, representing some clusters, are instrumented. The number of instrumented clusters per basic block is determined by an _instrumentation factor_ `W`. When `W = 0`, no cluster is instrumented, while `W = 100` means all clusters in the basic block are instrumented.
6. For each chosen cluster, some instrumentation code is inserted into the basic block, recording the computed address and the number of times it has been accessed in that basic block at that granularity.
7. To spare tracing overhead, a TLS buffer is injected by SMT into the target object file to temporarily store all accesses instrumented in a basic block. Prior to leaving that basic block, the buffer is flushed via a user-defined _flush function_.

Currently, Hijacker bundles SMT as a _preset_ which can be enabled in the rules file:

```
<?xml version="1.0"?>
<hijacker:Rules xmlns:hijacker="http://www.dis.uniroma1.it/~hpdcs/">
	<hijacker:Executable entryPoint="main_instr" initFunc="myinitfunc" finiFunc="myfinifunc" suffix="instr">

		<hijacker:Preset name="smtracer" function="myflushfunc" convention="stdcall">
			<hijacker:Param  name="instrfact"   value="1.00" />
			<hijacker:Param  name="chunksize"   value="0" />
			<hijacker:Param  name="tracestack"  value="true" />
		</hijacker:Preset>

	</hijacker:Executable>

</hijacker:Rules>
```

The relevant attributes and values for the purpose of using SMT are described below.

The attribute `entryPoint` instructs Hijacker to directly invoke the instrumented version of the program when it is launched. This is only needed if the input relocatable file comes with an actual `main()` function, otherwise the attribute _must_ be removed.

The attribute `initFunc` (optional) allows to install a custom _initialization function_ right before the actual entry point (see previous attribute) is invoked. The function accepts no parameters and returns no value. It must be provided (as a function internal to the module or, more commonly, as an external function) prior to the final linking step.

The attribute `finiFunc` (optional) allows to install a custom _finalization function_ right before the actual entry point (see previous attribute) is invoked. The function accepts no parameters and returns no value. It must be provided (as a function internal to the module or, more commonly, as an external function) prior to the final linking step.

The attribute `function` to the `Preset` tag specifies which _flush function_ will be invoked upon leaving a basic block. Currently, the size of this buffer is computed and tuned by SMT depending on the given object file. Details on the flush function are provided below.

The `instrfact` param is the _instrumentation factor_ provided to SMT. It has a range between 0 and 1, where 0 means that no memory access is ever instrumented, while 1 means all memory accesses are intercepted.

The `chunksize` param is the _chunk size_ used by SMT to determine how to cluster memory accesses. A value 0 means that accesses are treated at the granularity of a single byte, while a higher value determines a granularity computed as 2 to the `chunksize` (e.g., 4KB chunks are obtained by passing 12 as chunk size).

The `tracestack` parameter determines whether Hijacker will instrument stack accesses. Sometimes only accesses to the heap or static data sections are of interest.

[3] S. Economo, D. Cingolani, A. Pellegrini and F. Quaglia, "Configurable and Efficient Memory Access Tracing via Selective Expression-Based x86 Binary Instrumentation," 2016 IEEE 24th International Symposium on Modeling, Analysis and Simulation of Computer and Telecommunication Systems (MASCOTS), London, 2016, pp. 261-270.

Flush function
--------------
The signature for the flush function which will be invoked is:

```
void <function_name>(unsigned long start, unsigned long size);
```

where `start` is the address of the TLS buffer and `size` is the total number of entries in the buffer.

Each entry can be described by the following structure:

```
struct entry {
	unsigned long address;   // Computed address of this memory access
	unsigned long count;     // Number of times that address has been found (cluster cardinality)
	unsigned long bbid;      // ID of the basic-block that issued the access
}
```

A typical flush function will store the contents of the base TLS buffer into a larger buffer that will be eventually dumped to a file, or consumed at runtime by a dedicated thread or process daemon. To support the task of dumping the contents to a file and provided that a `main()` function can be found, a finalization function can be provided (see above).

An experimental implementation for a flush function that maintains a larger buffer which is eventually dumped to a file is provided under the `/lib` folder. Don't forget to link your own implementation to the final executable. Failing to do so would make the linker complain about missing symbols.
