sqlite3
-------

Copyright (c) 2012-2025 Sebastien Rombauts (sebastien.rombauts@gmail.com)

"sqlite3.c" and "sqlite3.h" files from sqlite-amalgamation-3540100.zip (SQLite 3.54.1 2026-10-16).

Source: https://sqlite.org/2026/sqlite-amalgamation-3540100.zip
Official archive SHA3-256: `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`.
This includes the FTS5 security correction released in 3.53.2 for
CVE-2026-11822 / CVE-2026-11824. The existing build options are unchanged.

Those files are provided for easy setup and compatibility under Windows/Linux/MacOS.
They are used by default by the CMake build.

Use -DSQLITECPP_INTERNAL_SQLITE=OFF to link against the Linux "libsqlite3-dev" package instead.

### License:

All of the code and documentation in SQLite has been dedicated to the public domain by the authors.
