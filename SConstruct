env = Environment()

env.Append( CXXFLAGS = "-std=c++17" )
env.Append( CCFLAGS = "-g" )
env.Append( CCFLAGS = "-Wall" )
env.Append( CPPPATH = "../../include" )
env.VariantDir("build", ".", duplicate = False)

Export("env")

env['libs'] = dict()

SConscript('build/src/SConstruct')
SConscript('build/test/SConstruct')
Default('build/src/clues')
