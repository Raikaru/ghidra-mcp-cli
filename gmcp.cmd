@echo off
rem -S -E: gmcp.py is stdlib-only, so skipping site-packages is free and avoids
rem a broken .pth in a user site-packages dir printing a traceback on every run.
python -S -E "%~dp0gmcp.py" %*
