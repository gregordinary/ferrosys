# Deterministic output

The default materialization is byte-reproducible: the same source and the same
inputs produce a byte-identical image on any machine.

Every value a filesystem would normally draw from its environment is an input
instead. The two such values are:

- the **filesystem UUID** is a 16-byte value supplied by the caller;
- **timestamps** are supplied by the caller.

A caller that wants clock- or random-derived values computes them and passes
them in explicitly, keeping that choice out of the default path.

Inode-number assignment is a fixed function of the source, in sorted path order,
so two runs over the same source assign identical inode numbers — and therefore
write identical bytes. Anything that reaches on-disk order (directory entries,
block groups) is sorted or otherwise fixed into a determinate order.
