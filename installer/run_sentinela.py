"""Ponto de entrada do executável empacotado (PyInstaller)."""
import sys

from sentinela.ui import main

sys.exit(main(sys.argv))
