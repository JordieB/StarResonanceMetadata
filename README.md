# Star Resonance Dumper

A tool for dumping BPSR global-metadata.dat from the memory dump file.

### Requirements
- python 3.9+ (v3.10+ or latest recommended)
- Dump file generated from the Task Manager [(?)](#how-to-dump-memory)

### How to dump
<img src=".github/how-to-dump.png" />
the .DMP file will be generated in Windows temporary folder (a popup of "Go to file" prompt will be shown), once generated move the .DMP file to the same directory where global-metadata-dumper.py is exist for the easier access.

### How to use
```sh
python global-metadata-dumper.py <.DMP file> <output.dat>
```

### Example
```sh
python global-metadata-dumperpy BPSR.DMP global-metadata.py
```
