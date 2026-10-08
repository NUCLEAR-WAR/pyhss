#!/usr/bin/env python3
"""Read-only ownership audit for explicit Cx profiles and legacy fallback."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from sqlalchemy import create_engine,text
from pyhss_config import config
from database import database_connection_settings

def main():
    url,args=database_connection_settings(config['database'])
    engine=create_engine(url,connect_args=args,echo=False)
    queries={
      'explicit_profiles':'SELECT COUNT(*) FROM ims_cx_profile',
      'explicit_identities':'SELECT COUNT(*) FROM ims_cx_identity',
      'runtime_states':'SELECT COUNT(*) FROM ims_cx_state',
      'legacy_only':'SELECT COUNT(*) FROM ims_subscriber i LEFT JOIN ims_cx_profile p ON p.ims_subscriber_id=i.ims_subscriber_id WHERE p.ims_subscriber_id IS NULL',
      'orphan_profiles':'SELECT COUNT(*) FROM ims_cx_profile p LEFT JOIN ims_subscriber i ON i.ims_subscriber_id=p.ims_subscriber_id WHERE i.ims_subscriber_id IS NULL',
      'orphan_identities':'SELECT COUNT(*) FROM ims_cx_identity x LEFT JOIN ims_cx_profile p ON p.ims_subscriber_id=x.ims_subscriber_id WHERE p.ims_subscriber_id IS NULL',
      'orphan_states':'SELECT COUNT(*) FROM ims_cx_state s LEFT JOIN ims_subscriber i ON i.ims_subscriber_id=s.ims_subscriber_id WHERE i.ims_subscriber_id IS NULL',
    }
    with engine.connect() as c:
      values={name:c.execute(text(sql)).scalar_one() for name,sql in queries.items()}
      for name,value in values.items():print(f'{name}: {value}')
    if any(values[k] for k in ('orphan_profiles','orphan_identities','orphan_states')):
      print('FAIL: orphan Cx records detected');return 1
    print('PASS: Cx ownership integrity (database-level)')
    return 0
if __name__=='__main__':raise SystemExit(main())
