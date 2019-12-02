env = Environment()

env.Append( CXXFLAGS = "-std=c++11" )
env.Append( CCFLAGS = "-g" )
env.VariantDir("build", "src", duplicate = False)

Export("env")
SConscript('build/SConstruct')
