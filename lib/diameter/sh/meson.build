libdiameter_sh_sources = files('''
    ogs-diameter-sh.h
    message.h

    dict.c
    message.c
'''.split())

libdiameter_sh_inc = include_directories('.')

libdiameter_sh = library('ogsdiameter-sh',
    sources : libdiameter_sh_sources,
    version : libogslib_version,
    c_args : libdiameter_common_cc_flags,
    include_directories : libdiameter_sh_inc,
    dependencies : libdiameter_common_dep,
    install : true)

libdiameter_sh_dep = declare_dependency(
    link_with : libdiameter_sh,
    include_directories : libdiameter_sh_inc,
    dependencies : libdiameter_common_dep)
