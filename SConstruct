import os
import sys
from pathlib import Path

try:
    # if there is already an environment then simply use that, some other
    # level of the build system already initialized it
    Import('env')
except Exception:
    try:
        from buildsystem import initSCons
    except ImportError:
        cosmos_scripts = Path(Dir('.').abspath) / 'libcosmos' / 'scripts'
        sys.path.append(str(cosmos_scripts))
        from buildsystem import initSCons
    env = initSCons('clues')

env.AddLocalLibrary('libcosmos')

env['project_root'] = str(Dir('.').get_abspath())

env = SConscript(env['buildroot'] + 'src/SConstruct')

instroot = Path(env['instroot'])

install_dev_files = env['install_dev_files']

if env['project'] == 'clues':
    SConscript(env['buildroot'] + 'test/SConstruct')
    SConscript(env['buildroot'] + 'test/cases/SConstruct')
    SConscript(env['buildroot'] + 'doc/SConstruct')
    Default(env['bins']['clues'])

if install_dev_files or env['libtype'] == 'shared':
    node = env.InstallVersionedLib(os.path.join(instroot, env['lib_base_dir']), env['libs']['libclues'])
    env.Alias('install', node)

if install_dev_files:
    env.InstallHeaders('clues')
    clues_bin = env.Install(instroot / 'bin', env['bins']['clues'])
    env.Alias('install', clues_bin)
