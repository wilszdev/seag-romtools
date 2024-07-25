# seag-romtools
a collection of little tools for seagate ROMs

## cloning
this repo uses submodules, so needs to be cloned with the `--recursive` option

```
git clone git@github.com:wilszdev/seag-romtools.git --recursive
```

## seag-rom2elf
tool for extracting useful portions of a ROM dump into a more workable format

an example invocation for a ROM dump `rom.bin` and a RAM dump `ram.bin` from
address 0x100000 is

```
python rom2elf.py -r -i rom.bin -o rom.elf 100000 ram.bin
```
