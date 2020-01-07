import os

prefix = os.environ.get("SCONS_CROSS_PREFIX", None)

env_options = {}

if prefix:
	env_options = {
	    "CC"    : "{prefix}-gcc",
	    "CXX"   : "{prefix}-g++",
	    "LD"    : "{prefix}-g++",
	    "AR"    : "{prefix}-ar",
	    "STRIP" : "{prefix}-strip",
	}

	for key in env_options:
		env_options[key] = env_options[key].format(prefix = prefix)

env = Environment(**env_options)

env.Append( CXXFLAGS = "-std=c++17" )
env.Append( CCFLAGS = "-g" )
if "CXXFLAGS" in os.environ:
	env.MergeFlags(os.environ["CXXFLAGS"])
env.Append( CCFLAGS = "-g" )
env.Append( CCFLAGS = "-Wall" )
env.Append( CPPPATH = "../../include" )
env.VariantDir("build", ".", duplicate = False)

Export("env")

env['libs'] = dict()

SConscript('build/src/SConstruct')
SConscript('build/test/SConstruct')
Default('build/src/clues')
