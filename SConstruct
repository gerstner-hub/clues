env = Environment()

env.Append( CXXFLAGS = "-std=c++11" )
env.Append( CCFLAGS = "-g" )
env.Append( CCFLAGS = "-Werror=return-type" )
env.VariantDir("build", "src", duplicate = False)

Export("env")
SConscript('build/SConstruct')
