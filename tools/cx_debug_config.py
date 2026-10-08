#!/usr/bin/env python3
"""Inspect effective PyHSS SQL logging settings without displaying credentials."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from pyhss_config import config
logging=config.get('logging',{})
print('sqlalchemy_sql_echo:',logging.get('sqlalchemy_sql_echo',False))
print('sqlalchemy_pool_recycle:',logging.get('sqlalchemy_pool_recycle',5))
print('sqlalchemy_pool_size:',logging.get('sqlalchemy_pool_size',30))
print('To suppress SQL statements: set logging.sqlalchemy_sql_echo: false in the effective config, then restart PyHSS.')
