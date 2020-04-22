# pefile-extract-icon #
This is a fork of [extract-icon-py](https://github.com/firodj/extract-icon-py/) that includes various improvements such as migrating to Python 3, easier extraction of icons that a Windows system would normally display and handling of exceptions that occur when parsing certain obfuscated PE files.

## Installing ##
* ``git clone https://github.com/57ur14/pefile-extract-icon.git``
* ``cd pefile-extract-icon``
* ``pip3 install --user -r requirements.txt``
* ``python3 setup.py install``

On some systems ``pip3`` have to be replaced with ``pip`` or ``python3 -m pip``.

## Usage ##
```
import extract_icon

icon_extractor = extract_icon.ExtractIcon('path/to/pe_executable.exe')
raw = icon_extractor.get_raw_windows_preferred_icon()
```
or - if a pefile object already is instantiated in your script:
```
import pefile

import extract_icon

pe = pefile.PE('path/to/pe_executable.exe')
icon_extractor = extract_icon.ExtractIcon(pefile_pe=pe)
raw = icon_extractor.get_raw_windows_preferred_icon()
```

## Uninstalling ##
``pip3 uninstall extract_icon``

## Changes ##
The following changes have been made from the original [project](https://github.com/firodj/extract-icon-py/tree/64e7b0bf3d2dfd6c673ca813117d8f80fe87a3ed):
* Migrated Python 3
* Replaced tabs with spaces
* Added the option of providing a pefile object instead of path to a pe executable (speeds up analysis if file already has been parsed by pefile)
* Added resillience with exception handling for exceptions that occur when parsing certain files
* Added the functions ``get_windows_preferred_icon`` and ``get_raw_windows_preferred_icon`` in ``extract_icon/__init__.py``
