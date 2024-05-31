# seag-romtools
a collection of little tools for seagate ROMs

## seag-rom2elf
tool for extracting useful portions of a ROM dump into a more workable format

it does technically work, but currently loads all the files from the whole ROM.
this isn't very smart as we get lots of overlapping segments in our ELF file.

