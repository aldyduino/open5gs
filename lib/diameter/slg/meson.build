libdiameter_slg_sources = files('''
    ogs-diameter-slg.h
    message.h
    message.c
'''.split())

libdiameter_slg_inc = include_directories('.')

libdiameter_slg = library('ogsdiameter-slg',
    sources : libdiameter_slg_sources,
    version : libogslib_version,
    c_args : libdiameter_common_cc_flags,
    include_directories : [libdiameter_slg_inc],
    dependencies : libdiameter_common_dep,
    install : true)

libdiameter_slg_dep = declare_dependency(
    link_with : libdiameter_slg,
    include_directories : [libdiameter_slg_inc],
    dependencies : libdiameter_common_dep)
