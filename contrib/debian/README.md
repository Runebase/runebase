
Debian
====================
This directory contains files used to package runebased/runebase-qt
for Debian-based Linux systems. If you compile runebased/runebase-qt yourself, there are some useful files here.

## runebase: URI support ##


runebase-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install runebase-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your runebase-qt binary to `/usr/bin`
and the `../../share/pixmaps/bitcoin128.png` to `/usr/share/pixmaps`

runebase-qt.protocol (KDE)

