#!/usr/bin/env python3
"""Run BoJangles tests with every frontend store under a temporary authority root."""
from pathlib import Path
import os,subprocess,sys,tempfile
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='bojangles-isolated-tests-') as temporary:
 home=Path(temporary)
 env=os.environ.copy()
 env.update(HOME=str(home),XDG_DATA_HOME=str(home/'data'),XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_STATE_HOME=str(home/'state'),PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=os.pathsep.join([str(root/'src'),str(root/'tests')]))
 result=subprocess.run([sys.executable,'-m','unittest',*sys.argv[1:]],cwd=root,env=env)
 raise SystemExit(result.returncode)
