# YARA 30 Easy Examples


Folders:
- samples/: 30 simulated files (text/scripts/binary-magics)
- rules/:   30 YARA rules (1:1 mapping by example number)


Usage quickstart:
  yara -r rules samples/

Notes:
- Binary files with PE/ELF/ZIP/PDF/JPEG signatures are minimal and **not functional** executables, just enough for string/hex/YARA practice.
- Rules avoid 'pe.imports()' to ensure matches work with these simulated files.
